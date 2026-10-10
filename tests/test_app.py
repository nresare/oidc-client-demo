import re
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from starlette.responses import Response
from starlette.testclient import TestClient

from oidc_client_demo.app import create_app, create_hypercorn_config, run_server
from oidc_client_demo.auth import OidcInitializationError
from oidc_client_demo.config import AppConfig


@pytest.fixture
def config_file(tmp_path):
    (tmp_path / "session-key").write_text("test-secret")
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[app]
secret_key_path = "session-key"
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
    (tmp_path / "session-key").write_text("test-secret")
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f"""
[app]
secret_key_path = "session-key"
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


def csrf_from_profile(client: TestClient) -> str:
    response = client.get("/profile")
    result = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert result is not None
    return result.group(1)


def test_home_page_shows_login(monkeypatch, config_file, oidc_client):
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Sign in with OIDC" in response.text


def test_healthz_returns_ok(monkeypatch, config_file, oidc_client):
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"status": "ok"}


def test_static_stylesheet_is_served_from_package(monkeypatch, config_file, oidc_client):
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        response = client.get("/static/site.css")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ":root" in response.text


def test_profile_redirects_when_logged_out(monkeypatch, config_file, oidc_client):
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        response = client.get("/profile", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"] == "/login"


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
    assert response.headers["location"] == "/profile"
    assert profile_response.status_code == 200
    assert "test@example.com" in profile_response.text


def test_token_experiment_refreshes_and_calls_graph(monkeypatch, config_file, oidc_client):
    oidc_client.load_server_metadata.return_value = {"token_endpoint": "https://idp.example/token"}
    oidc_client.authorize_access_token.return_value = {
        "userinfo": {"email": "test@example.com"},
        "access_token": "old-access",
        "refresh_token": "old-refresh",
        "expires_in": 3600,
        "scope": "User.Read offline_access",
    }
    refresh = AsyncMock(return_value={"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600})
    graph = AsyncMock(return_value=200)
    monkeypatch.setattr("oidc_client_demo.app.refresh_access_token", refresh)
    monkeypatch.setattr("oidc_client_demo.app.call_graph_me", graph)

    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        client.get("/auth/callback")
        csrf = csrf_from_profile(client)
        assert client.post("/refresh", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
        page = client.get("/profile")
        assert "Refresh succeeded" in page.text
        assert "Replacement refresh token received: yes" in page.text
        assert "Refresh token changed: yes" in page.text
        assert "old-refresh" not in page.text
        assert "new-refresh" not in page.text
        assert "old-refresh" not in client.cookies.get("session", "")
        assert "new-refresh" not in client.cookies.get("session", "")
        assert client.post("/graph-me", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
        assert "Graph /me returned HTTP 200" in client.get("/profile").text
        client.get("/logout", follow_redirects=False)
        assert not client.app.state.token_store

    refresh.assert_awaited_once_with("https://idp.example/token", "test-client", None, "old-refresh")
    graph.assert_awaited_once_with("new-access")


def test_refresh_failure_and_missing_token(monkeypatch, config_file, oidc_client):
    oidc_client.load_server_metadata.return_value = {"token_endpoint": "https://idp.example/token"}
    oidc_client.authorize_access_token.return_value = {
        "userinfo": {"email": "test@example.com"},
        "access_token": "old-access",
        "refresh_token": "old-refresh",
    }
    refresh = AsyncMock(return_value={"error": "invalid_grant"})
    monkeypatch.setattr("oidc_client_demo.app.refresh_access_token", refresh)
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        client.get("/auth/callback")
        csrf = csrf_from_profile(client)
        assert client.post("/refresh", data={"csrf_token": "wrong"}).status_code == 403
        client.post("/refresh", data={"csrf_token": csrf})
        assert "Refresh failed: invalid_grant" in client.get("/profile").text
        assert next(iter(client.app.state.token_store.values())).refresh_token == "old-refresh"

        next(iter(client.app.state.token_store.values())).refresh_token = None
        client.post("/refresh", data={"csrf_token": csrf})
        assert "No refresh token was issued" in client.get("/profile").text
    refresh.assert_awaited_once()


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
    config = create_hypercorn_config(AppConfig(secret_key="test"))

    assert config.certfile is None
    assert config.keyfile is None
    assert not config.ssl_enabled
    assert config.bind == ["0.0.0.0:8080"]
    assert config.accesslog == "-"
    assert config.errorlog == "-"


@pytest.mark.anyio
async def test_run_server_wraps_oidc_startup_errors(monkeypatch, config_file, oidc_client):
    oidc_client.load_server_metadata.side_effect = httpx2.ConnectTimeout("timed out")
    monkeypatch.setattr("oidc_client_demo.auth.register_oidc_client", lambda app, oidc_config: oidc_client)
    app = create_app(str(config_file))

    with pytest.raises(OidcInitializationError, match="Unable to load OIDC provider metadata"):
        await run_server(app, create_hypercorn_config(AppConfig(secret_key="test")))


@pytest.mark.parametrize(
    "route, destination", [("/auth/callback", "/profile"), ("/profile", "/login"), ("/logout", "/")]
)
def test_local_redirects_preserve_public_origin(monkeypatch, tmp_path, oidc_client, route, destination):
    config_file = write_config(tmp_path, "https://demo.resare.com")
    oidc_client.authorize_access_token.return_value = {"userinfo": {"email": "test@example.com"}}
    with create_test_client(monkeypatch, config_file, oidc_client, base_url="http://demo.resare.com") as client:
        response = client.get(route, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == destination


def test_request_tracing_exports_one_span_per_request(monkeypatch, config_file, oidc_client):
    from opentelemetry.sdk.trace.export import SpanExportResult
    from opentelemetry.trace import SpanKind, StatusCode

    exporter = Mock()
    exporter.export.return_value = SpanExportResult.SUCCESS
    monkeypatch.setattr("oidc_client_demo.tracing.OTLPSpanExporter", lambda **kwargs: exporter)
    with config_file.open("a") as f:
        f.write('\n[otel]\nendpoint = "http://tempo:4318/v1/traces"\n')
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        assert client.get("/healthz?code=secret").status_code == 200
        assert client.get("/missing").status_code == 404
        assert client.get("/static/site.css").status_code == 200
        oidc_client.authorize_access_token.side_effect = RuntimeError("secret-token")
        with pytest.raises(RuntimeError):
            client.get("/auth/callback?code=secret-token")
    spans = [span for call in exporter.export.call_args_list for span in call.args[0]]
    assert len(spans) == 4
    assert len({span.context.trace_id for span in spans}) == 4
    assert all(span.kind == SpanKind.SERVER for span in spans)
    assert all(span.resource.attributes["service.name"] == "oidc-client-demo" for span in spans)
    assert [span.attributes["http.response.status_code"] for span in spans] == [200, 404, 200, 500]
    assert spans[-1].status.status_code == StatusCode.ERROR
    assert "secret" not in str([(span.attributes, span.events, span.status.description) for span in spans])
    exporter.shutdown.assert_called_once()


def test_request_tracing_disabled(monkeypatch, config_file, oidc_client):
    factory = Mock()
    monkeypatch.setattr("oidc_client_demo.app.create_tracer_provider", factory)
    with create_test_client(monkeypatch, config_file, oidc_client) as client:
        assert client.get("/healthz").status_code == 200
    factory.assert_not_called()


def test_request_tracing_submits_otlp_http(monkeypatch, config_file, oidc_client):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Receiver)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with config_file.open("a") as f:
            f.write(f'\n[otel]\nendpoint = "http://127.0.0.1:{server.server_port}/v1/traces"\n')
        with create_test_client(monkeypatch, config_file, oidc_client) as client:
            assert client.get("/healthz").status_code == 200
        assert len(received) == 1
        path, body = received[0]
        assert path == "/v1/traces"
        request = ExportTraceServiceRequest.FromString(body)
        spans = [span for resource in request.resource_spans for scope in resource.scope_spans for span in scope.spans]
        assert len(spans) == 1
        assert spans[0].name == "GET"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.mark.anyio
async def test_run_server_uses_tls_settings(monkeypatch, config_file, oidc_client):
    monkeypatch.setattr("oidc_client_demo.auth.register_oidc_client", lambda app, oidc_config: oidc_client)
    app = create_app(str(config_file))
    app.state.settings.app.tls_cert_path = "/cert.pem"
    app.state.settings.app.tls_key_path = "/key.pem"
    serve = AsyncMock()
    monkeypatch.setattr("oidc_client_demo.app.serve", serve)

    await run_server(app)

    config = serve.call_args.args[1]
    assert config.bind == ["0.0.0.0:8443"]
    assert config.certfile == "/cert.pem"
    assert config.keyfile == "/key.pem"
    assert config.ssl_enabled
    assert config.alpn_protocols == ["h2", "http/1.1"]
