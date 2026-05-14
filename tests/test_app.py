from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlparse

import pytest
import httpx
from starlette.responses import Response
from starlette.testclient import TestClient

from oidc_client_demo.app import create_app, create_hypercorn_config, run_server
from oidc_client_demo.auth import OidcInitializationError


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


@pytest.fixture
def oidc_client():
    client = Mock()
    client.load_server_metadata = AsyncMock(return_value={})
    client.authorize_access_token = AsyncMock()
    client.authorize_redirect = AsyncMock(return_value=Mock(status_code=302, headers={"location": "/auth"}))
    client.userinfo = AsyncMock()
    return client


def create_test_client(monkeypatch, config_file, oidc_client, base_url: str = "http://testserver"):
    monkeypatch.setattr("oidc_client_demo.auth.register_oidc_client", lambda app, oidc_config: oidc_client)
    app = create_app(str(config_file))
    return TestClient(app, base_url=base_url)


def write_config(tmp_path, base_url: str):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f"""
[app]
secret_key = "test-secret"
base_url = "{base_url}"

[oidc]
issuer = "http://localhost:9000"
client_id = "test-client"
""".strip()
    )
    return config_path


def login_user(client: TestClient, oidc_client: Mock, userinfo: dict[str, str]) -> None:
    oidc_client.authorize_access_token.return_value = {"userinfo": userinfo}
    response = client.get("/auth/callback", follow_redirects=False)
    assert response.status_code == 302


def test_home_page_shows_login(monkeypatch, config_file, oidc_client):
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Sign in with OIDC" in response.text


def test_profile_redirects_when_logged_out(monkeypatch, config_file, oidc_client):
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        response = client.get("/profile", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"].endswith("/login")


def test_callback_stores_user_in_session(monkeypatch, config_file, oidc_client):
    oidc_client.authorize_access_token.return_value = {
        "userinfo": {
            "sub": "abc123",
            "name": "Test User",
            "preferred_username": "tester",
            "email": "test@example.com",
        }
    }

    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        response = client.get("/auth/callback", follow_redirects=False)
        profile_response = client.get("/profile")

    assert response.status_code == 302
    assert response.headers["location"].endswith("/profile")
    assert profile_response.status_code == 200
    assert "test@example.com" in profile_response.text


def test_profile_page_shows_only_email(monkeypatch, config_file, oidc_client):
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        login_user(
            client,
            oidc_client,
            {
                "sub": "abc123",
                "name": "Test User",
                "preferred_username": "tester",
                "email": "test@example.com",
            },
        )
        response = client.get("/profile")

    assert response.status_code == 200
    assert "Email" in response.text
    assert "test@example.com" in response.text
    assert "Name" not in response.text
    assert "Username" not in response.text
    assert "Test User" not in response.text
    assert "tester" not in response.text


def test_home_page_does_not_show_name_when_logged_in(monkeypatch, config_file, oidc_client):
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        login_user(
            client,
            oidc_client,
            {
                "name": "Test User",
                "email": "test@example.com",
            },
        )
        response = client.get("/")

    assert response.status_code == 200
    assert "You are signed in." in response.text
    assert "Test User" not in response.text


def test_login_uses_configured_base_url_for_redirect_uri(monkeypatch, tmp_path, oidc_client):
    config_file = write_config(tmp_path, "https://demo.resare.com")
    oidc_client.authorize_redirect.return_value = Response(status_code=204)

    with create_test_client(monkeypatch, config_file, oidc_client, base_url="http://demo.resare.com") as client:
        response = client.get("/login")

    assert response.status_code == 204
    oidc_client.authorize_redirect.assert_awaited_once()
    assert oidc_client.authorize_redirect.call_args.args[1] == "https://demo.resare.com/auth/callback"


def test_logout_uses_configured_base_url_for_post_logout_redirect(monkeypatch, tmp_path, oidc_client):
    config_file = write_config(tmp_path, "https://demo.resare.com/")
    oidc_client.load_server_metadata.return_value = {"end_session_endpoint": "https://idp.example/logout"}

    with create_test_client(monkeypatch, config_file, oidc_client, base_url="http://demo.resare.com") as client:
        response = client.get("/logout", follow_redirects=False)

    assert response.status_code == 302
    location = urlparse(response.headers["location"])
    query = parse_qs(location.query)
    assert query["post_logout_redirect_uri"] == ["https://demo.resare.com/"]


def test_create_hypercorn_config_sets_runtime_defaults():
    config = create_hypercorn_config()

    assert config.bind == ["0.0.0.0:8080"]
    assert config.accesslog == "-"
    assert config.errorlog == "-"


@pytest.mark.anyio
async def test_run_server_wraps_oidc_startup_errors(monkeypatch, config_file, oidc_client):
    oidc_client.load_server_metadata.side_effect = httpx.ConnectTimeout("timed out")
    monkeypatch.setattr("oidc_client_demo.auth.register_oidc_client", lambda app, oidc_config: oidc_client)
    app = create_app(str(config_file))

    with pytest.raises(OidcInitializationError, match="Unable to load OIDC provider metadata"):
        await run_server(app, create_hypercorn_config())
