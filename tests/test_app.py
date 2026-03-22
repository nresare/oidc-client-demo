from unittest.mock import Mock

import pytest

from website_with_login.app import StandaloneApplication, create_app
from website_with_login.auth import configure_oidc


@pytest.fixture
def config_file(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[app]
secret_key = "test-secret"
base_url = "http://localhost:8080"

[oidc]
issuer = "http://localhost:9000"
client_id = "test-client"
""".strip()
    )
    return config_path


def test_home_page_shows_login(monkeypatch, config_file):
    oidc_client = Mock()
    monkeypatch.setenv("CONFIG_PATH", str(config_file))
    monkeypatch.setattr("website_with_login.auth.register_oidc_client", lambda app, oidc_config: oidc_client)
    oidc_client.load_server_metadata.return_value = {}

    app = create_app()
    configure_oidc(app)
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"Sign in with OIDC" in response.data


def test_profile_redirects_when_logged_out(monkeypatch, config_file):
    oidc_client = Mock()
    monkeypatch.setenv("CONFIG_PATH", str(config_file))
    monkeypatch.setattr("website_with_login.auth.register_oidc_client", lambda app, oidc_config: oidc_client)
    oidc_client.load_server_metadata.return_value = {}

    app = create_app()
    configure_oidc(app)
    client = app.test_client()

    response = client.get("/profile")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_callback_stores_user_in_session(monkeypatch, config_file):
    oidc_client = Mock()
    oidc_client.authorize_access_token.return_value = {
        "userinfo": {
            "sub": "abc123",
            "name": "Test User",
            "preferred_username": "tester",
            "email": "test@example.com",
        }
    }
    monkeypatch.setenv("CONFIG_PATH", str(config_file))
    monkeypatch.setattr("website_with_login.auth.register_oidc_client", lambda app, oidc_config: oidc_client)
    oidc_client.load_server_metadata.return_value = {}

    app = create_app()
    configure_oidc(app)
    client = app.test_client()

    response = client.get("/auth/callback")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/profile")

    with client.session_transaction() as session:
        assert session["user"]["sub"] == "abc123"
        assert session["user"]["name"] == "Test User"


def test_standalone_application_sets_gunicorn_hooks(monkeypatch, config_file):
    oidc_client = Mock()
    oidc_client.load_server_metadata.return_value = {}
    monkeypatch.setenv("CONFIG_PATH", str(config_file))
    monkeypatch.setattr("website_with_login.auth.register_oidc_client", lambda app, oidc_config: oidc_client)

    app = create_app()
    standalone = StandaloneApplication(app, {"bind": "127.0.0.1:8080", "workers": 1})

    assert standalone.cfg.settings["control_socket_disable"].value is True
    post_fork = standalone.cfg.settings["post_fork"].value
    assert callable(post_fork)

    post_fork(None, None)

    assert app.extensions["oidc_client"] is oidc_client
