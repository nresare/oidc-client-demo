# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

import click
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from hypercorn.typing import Framework
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from oidc_client_demo.auth import (
    OidcInitializationError,
    configure_oidc,
    get_oidc_client,
    get_oidc_metadata,
    login_required,
)
from oidc_client_demo.config import load_config

logger = logging.getLogger(__name__)

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


async def home(request: Request) -> Response:
    return TEMPLATES.TemplateResponse(
        request,
        "home.html",
        {
            "now": datetime.now(UTC),
            "user": request.session.get("user"),
        },
    )


async def login(request: Request) -> Response:
    oidc = get_oidc_client(request.app)
    redirect_uri = str(request.url_for("auth_callback"))
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
    return RedirectResponse(url=request.url_for("profile"), status_code=302)


@login_required
async def profile(request: Request) -> Response:
    return TEMPLATES.TemplateResponse(
        request,
        "profile.html",
        {
            "user": request.session["user"],
        },
    )


async def logout(request: Request) -> Response:
    request.session.clear()

    metadata = get_oidc_metadata(request.app)
    end_session_endpoint = metadata.get("end_session_endpoint")
    if end_session_endpoint:
        post_logout_redirect_uri = str(request.url_for("home"))
        query = urlencode({"post_logout_redirect_uri": post_logout_redirect_uri})
        return RedirectResponse(url=f"{end_session_endpoint}?{query}", status_code=302)

    return RedirectResponse(url=request.url_for("home"), status_code=302)


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
        await configure_oidc(app)
        yield

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
            Route("/login", login, name="login"),
            Route("/auth/callback", auth_callback, name="auth_callback"),
            Route("/profile", profile, name="profile"),
            Route("/logout", logout, name="logout"),
        ],
        middleware=middleware,
        lifespan=lifespan,
    )
    app.state.settings = config
    app.state.base_url = config.app.base_url.rstrip("/")
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
