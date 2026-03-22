# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

from collections.abc import Callable
from functools import wraps
from typing import Any

from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, session, url_for

from oidc_client_demo.config import Config, OidcConfig

OIDC_CLIENT_EXTENSION = "oidc_client"
OIDC_METADATA_EXTENSION = "oidc_server_metadata"


def register_oidc_client(app: Flask, oidc_config: OidcConfig) -> Any:
    oauth = OAuth(app)
    return oauth.register(
        name="oidc",
        client_id=oidc_config.client_id,
        server_metadata_url=oidc_config.server_metadata_url,
        client_kwargs={"scope": " ".join(oidc_config.scopes)},
        code_challenge_method="S256",
    )


def configure_oidc(app: Flask) -> None:
    config = app.config["APP_SETTINGS"]
    assert isinstance(config, Config)

    client = register_oidc_client(app, config.oidc)
    metadata = client.load_server_metadata()

    app.extensions[OIDC_CLIENT_EXTENSION] = client
    app.extensions[OIDC_METADATA_EXTENSION] = metadata


def get_oidc_client(app: Flask) -> Any:
    client = app.extensions.get(OIDC_CLIENT_EXTENSION)
    if client is None:
        raise RuntimeError("OIDC client is not initialized for this worker")
    return client


def get_oidc_metadata(app: Flask) -> dict[str, Any]:
    metadata = app.extensions.get(OIDC_METADATA_EXTENSION)
    if metadata is None:
        raise RuntimeError("OIDC metadata is not initialized for this worker")
    return metadata


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped_view(*args: Any, **kwargs: Any) -> Any:
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view
