# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

import logging
import os
from datetime import UTC, datetime
from urllib.parse import urlencode

import gunicorn.app.base
from flask import Flask, redirect, render_template, session, url_for
from gunicorn.config import Config as GunicornConfig

from oidc_client_demo.auth import configure_oidc, get_oidc_client, get_oidc_metadata, login_required
from oidc_client_demo.config import load_config

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__)

    config_path = "/config/config.toml"
    config = load_config(config_path)

    app.config["SECRET_KEY"] = config.app.secret_key
    app.config["APP_SETTINGS"] = config
    app.config["BASE_URL"] = config.app.base_url.rstrip("/")

    @app.route("/")
    def home():
        return render_template(
            "home.html",
            now=datetime.now(UTC),
            user=session.get("user"),
        )

    @app.route("/login")
    def login():
        oidc = get_oidc_client(app)
        redirect_uri = f"{app.config['BASE_URL']}{url_for('auth_callback')}"
        return oidc.authorize_redirect(redirect_uri)

    @app.route("/auth/callback")
    def auth_callback():
        oidc = get_oidc_client(app)
        token = oidc.authorize_access_token()
        user_info = token.get("userinfo")
        if not user_info:
            user_info = oidc.userinfo()

        session["user"] = {
            "sub": user_info.get("sub"),
            "preferred_username": user_info.get("preferred_username"),
            "name": user_info.get("name"),
            "email": user_info.get("email"),
        }
        return redirect(url_for("profile"))

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html", user=session["user"])

    @app.route("/logout")
    def logout():
        session.clear()

        metadata = get_oidc_metadata(app)
        end_session_endpoint = metadata.get("end_session_endpoint")
        if end_session_endpoint:
            post_logout_redirect_uri = f"{app.config['BASE_URL']}{url_for('home')}"
            query = urlencode({"post_logout_redirect_uri": post_logout_redirect_uri})
            return redirect(f"{end_session_endpoint}?{query}")

        return redirect(url_for("home"))

    return app


class StandaloneApplication(gunicorn.app.base.BaseApplication):
    def __init__(self, app: Flask, options: dict[str, str | int]) -> None:
        self.options = options
        self.application = app
        super().__init__()

    def _post_fork(self, server: object, worker: object) -> None:
        del server
        del worker
        configure_oidc(self.application)

    def load_config(self) -> None:
        for key, value in self.options.items():
            assert isinstance(self.cfg, GunicornConfig)
            self.cfg.set(key, value)
        assert isinstance(self.cfg, GunicornConfig)
        self.cfg.set("control_socket_disable", True)
        self.cfg.set("post_fork", self._post_fork)

    def load(self) -> Flask:
        return self.application


def setup_logging() -> None:
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S %z")

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


def main() -> None:
    setup_logging()
    logger.info("Starting application")
    app = create_app()
    options = {
        "bind": "0.0.0.0:8080",
        "workers": 4,
        "accesslog": "-",
        "errorlog": "-",
    }
    StandaloneApplication(app, options).run()


if __name__ == "__main__":
    main()
