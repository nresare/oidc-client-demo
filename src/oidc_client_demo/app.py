# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlencode

import click
import httpx2
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from hypercorn.typing import Framework
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.types import ASGIApp

from oidc_client_demo.auth import (
    OidcInitializationError,
    configure_oidc,
    get_oidc_client,
    get_oidc_metadata,
    login_required,
)
from oidc_client_demo.config import load_config
from oidc_client_demo.tokens import TokenRecord, call_graph_me, refresh_access_token, token_expiry
from oidc_client_demo.tracing import RequestTracingMiddleware, create_tracer_provider

logger = logging.getLogger(__name__)

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def external_url(request: Request, path: str) -> str:
    return f"{request.app.state.base_url}{path}"


async def home(request: Request) -> Response:
    return TEMPLATES.TemplateResponse(
        request,
        "home.html",
        {
            "now": datetime.now(UTC),
            "user": request.session.get("user"),
        },
    )


async def healthz(request: Request) -> Response:
    return JSONResponse({"status": "ok"})


async def login(request: Request) -> Response:
    oidc = get_oidc_client(request.app)
    redirect_uri = external_url(request, "/auth/callback")
    return await oidc.authorize_redirect(request, redirect_uri)


async def auth_callback(request: Request) -> Response:
    oidc = get_oidc_client(request.app)
    token = await oidc.authorize_access_token(request)
    user_info = token.get("userinfo")
    if not user_info:
        user_info = await oidc.userinfo(token=token)

    request.session["user"] = {
        "sub": user_info.get("sub"),
        "preferred_username": user_info.get("preferred_username"),
        "name": user_info.get("name"),
        "email": user_info.get("email"),
    }
    old_session_id = request.session.get("demo_session_id")
    if old_session_id:
        request.app.state.token_store.pop(old_session_id, None)
    session_id = secrets.token_urlsafe(32)
    request.session["demo_session_id"] = session_id
    request.session["demo_csrf"] = secrets.token_urlsafe(32)
    request.app.state.token_store[session_id] = TokenRecord.from_response(token)
    return RedirectResponse(url="/profile", status_code=302)


@login_required
async def profile(request: Request) -> Response:
    record = request.app.state.token_store.get(request.session.get("demo_session_id"))
    return TEMPLATES.TemplateResponse(
        request,
        "profile.html",
        {
            "user": request.session["user"],
            "token": record,
            "csrf_token": request.session.get("demo_csrf"),
        },
    )


def session_tokens(request: Request) -> TokenRecord | None:
    return request.app.state.token_store.get(request.session.get("demo_session_id"))


async def valid_demo_post(request: Request) -> bool:
    submitted = parse_qs((await request.body()).decode("utf-8")).get("csrf_token", [""])[0]
    expected = request.session.get("demo_csrf", "")
    return bool(expected) and secrets.compare_digest(submitted, expected)


@login_required
async def refresh_now(request: Request) -> Response:
    if not await valid_demo_post(request):
        return Response(status_code=403)
    record = session_tokens(request)
    if record is None or not record.refresh_token:
        if record:
            record.last_refresh = "No refresh token was issued. Check the offline_access scope."
        return RedirectResponse(url="/profile", status_code=303)

    config = request.app.state.settings.oidc
    endpoint = get_oidc_metadata(request.app).get("token_endpoint")
    if not endpoint:
        record.last_refresh = "The provider metadata has no token endpoint."
        return RedirectResponse(url="/profile", status_code=303)
    try:
        result = await refresh_access_token(endpoint, config.client_id, config.client_secret, record.refresh_token)
    except httpx2.HTTPError:
        record.last_refresh = "The token endpoint could not be reached."
        return RedirectResponse(url="/profile", status_code=303)

    if "error" in result:
        record.last_refresh = f"Refresh failed: {result['error']}. Sign in again if the token expired or was revoked."
    elif not result.get("access_token"):
        record.last_refresh = "Refresh failed: the response contained no access token."
    else:
        access_changed = result["access_token"] != record.access_token
        replacement = result.get("refresh_token")
        refresh_changed = bool(replacement and replacement != record.refresh_token)
        record.access_token = result["access_token"]
        if replacement:
            record.refresh_token = replacement
        record.expires_at = token_expiry(result)
        record.scope = result.get("scope", record.scope)
        record.last_graph = None
        record.last_refresh = (
            f"Refresh succeeded at {datetime.now(UTC).isoformat()}. "
            f"Access token changed: {'yes' if access_changed else 'no'}. "
            f"Replacement refresh token received: {'yes' if replacement else 'no'}. "
            f"Refresh token changed: {'yes' if refresh_changed else 'no'}."
        )
    return RedirectResponse(url="/profile", status_code=303)


@login_required
async def graph_me(request: Request) -> Response:
    if not await valid_demo_post(request):
        return Response(status_code=403)
    record = session_tokens(request)
    if record is None or not record.access_token:
        if record:
            record.last_graph = "No access token is available."
        return RedirectResponse(url="/profile", status_code=303)
    try:
        status = await call_graph_me(record.access_token)
        record.last_graph = f"Microsoft Graph /me returned HTTP {status} at {datetime.now(UTC).isoformat()}."
    except httpx2.HTTPError:
        record.last_graph = "Microsoft Graph could not be reached."
    return RedirectResponse(url="/profile", status_code=303)


async def logout(request: Request) -> Response:
    session_id = request.session.get("demo_session_id")
    if session_id:
        request.app.state.token_store.pop(session_id, None)
    request.session.clear()

    metadata = get_oidc_metadata(request.app)
    end_session_endpoint = metadata.get("end_session_endpoint")
    if end_session_endpoint:
        post_logout_redirect_uri = external_url(request, "/")
        query = urlencode({"post_logout_redirect_uri": post_logout_redirect_uri})
        return RedirectResponse(url=f"{end_session_endpoint}?{query}", status_code=302)

    return RedirectResponse(url="/", status_code=302)


def create_hypercorn_config() -> HypercornConfig:
    config = HypercornConfig()
    config.bind = ["0.0.0.0:8080"]
    config.accesslog = "-"
    config.errorlog = "-"
    return config


def create_app(config_path: str = "config.toml") -> Starlette:
    config = load_config(config_path)

    @asynccontextmanager
    async def lifespan(app: Starlette):
        provider = create_tracer_provider(config.otel) if config.otel else None
        app.state.tracer_provider = provider
        original_stack = app.middleware_stack
        if provider:
            app.middleware_stack = RequestTracingMiddleware(
                cast(ASGIApp, original_stack), tracer=provider.get_tracer("oidc_client_demo")
            )
        try:
            await configure_oidc(app)
            yield
        finally:
            if provider:
                app.middleware_stack = original_stack
                await asyncio.to_thread(provider.shutdown)

    middleware = [
        Middleware(
            SessionMiddleware,
            secret_key=config.app.secret_key,
            https_only=config.app.base_url.startswith("https://"),
        )
    ]

    app = Starlette(
        debug=False,
        routes=[
            Route("/", home, name="home"),
            Route("/healthz", healthz, name="healthz"),
            Route("/login", login, name="login"),
            Route("/auth/callback", auth_callback, name="auth_callback"),
            Route("/profile", profile, name="profile"),
            Route("/refresh", refresh_now, methods=["POST"], name="refresh_now"),
            Route("/graph-me", graph_me, methods=["POST"], name="graph_me"),
            Route("/logout", logout, name="logout"),
            Mount("/static", StaticFiles(packages=[("oidc_client_demo", "static")]), name="static"),
        ],
        middleware=middleware,
        lifespan=lifespan,
    )
    app.state.settings = config
    app.state.base_url = config.app.base_url.rstrip("/")
    app.state.token_store = {}
    return app


async def run_server(app: Starlette, config: HypercornConfig | None = None) -> None:
    await configure_oidc(app)
    await serve(cast(Framework, app), config or create_hypercorn_config())


def setup_logging() -> None:
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S %z")

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


@click.command()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    default="config.toml",
    help="Path to the configuration file.",
)
def main(config: str) -> None:
    setup_logging()
    logger.info("Starting application")
    app = create_app(config)
    try:
        asyncio.run(run_server(app))
    except OidcInitializationError as exc:
        raise click.ClickException(str(exc)) from None


if __name__ == "__main__":
    main()
