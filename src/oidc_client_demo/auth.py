# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any

from authlib.integrations.starlette_client import OAuth
import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from oidc_client_demo.config import Config, OidcConfig

OIDC_CLIENT_STATE_KEY = "oidc_client"
OIDC_METADATA_STATE_KEY = "oidc_server_metadata"


class OidcInitializationError(RuntimeError):
    """Raised when the OIDC client cannot be initialized cleanly."""


def register_oidc_client(app: Starlette, oidc_config: OidcConfig) -> Any:
    del app
    oauth = OAuth()
    return oauth.register(
        name="oidc",
        client_id=oidc_config.client_id,
        server_metadata_url=oidc_config.server_metadata_url,
        client_kwargs={"scope": " ".join(oidc_config.scopes)},
        code_challenge_method="S256",
    )


async def configure_oidc(app: Starlette) -> None:
    existing_client = getattr(app.state, OIDC_CLIENT_STATE_KEY, None)
    existing_metadata = getattr(app.state, OIDC_METADATA_STATE_KEY, None)
    if existing_client is not None and existing_metadata is not None:
        return

    config = app.state.settings
    assert isinstance(config, Config)

    client = register_oidc_client(app, config.oidc)
    try:
        metadata = await client.load_server_metadata()
    except httpx.HTTPError as exc:
        raise OidcInitializationError(
            "Unable to load OIDC provider metadata from "
            f"{config.oidc.server_metadata_url}: {exc.__class__.__name__}. "
            "Check that the issuer URL is correct and reachable."
        ) from exc

    app.state.oidc_client = client
    app.state.oidc_server_metadata = metadata


def get_oidc_client(app: Starlette) -> Any:
    client = getattr(app.state, OIDC_CLIENT_STATE_KEY, None)
    if client is None:
        raise RuntimeError("OIDC client is not initialized for this worker")
    return client


def get_oidc_metadata(app: Starlette) -> dict[str, Any]:
    metadata = getattr(app.state, OIDC_METADATA_STATE_KEY, None)
    if metadata is None:
        raise RuntimeError("OIDC metadata is not initialized for this worker")
    return metadata


def login_required(
    view: Callable[..., Awaitable[Response]],
) -> Callable[..., Awaitable[Response]]:
    @wraps(view)
    async def wrapped_view(request: Request, *args: Any, **kwargs: Any) -> Response:
        if "user" not in request.session:
            return RedirectResponse(url=request.url_for("login"), status_code=302)
        return await view(request, *args, **kwargs)

    return wrapped_view
