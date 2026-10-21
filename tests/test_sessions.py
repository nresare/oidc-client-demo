import json
import time

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from oidc_client_demo.sessions import SESSION_MAX_AGE, EncryptedSessionMiddleware


def session_app(secret="test-secret", https_only=False):
    async def read(request: Request):
        return JSONResponse(dict(request.session))

    async def write(request: Request):
        request.session["refresh_token"] = "private-token"
        return JSONResponse({"ok": True})

    return Starlette(
        routes=[Route("/", read), Route("/write", write)],
        middleware=[Middleware(EncryptedSessionMiddleware, secret_key=secret, https_only=https_only)],
    )


@pytest.mark.parametrize("invalid", ["tampered", "expired", "wrong-key", "not-dict", "invalid-json", "legacy"])
def test_invalid_sessions_are_unauthenticated(invalid):
    app = session_app()
    cipher = EncryptedSessionMiddleware(app, "test-secret").cipher
    data = b'{"user":{"email":"private@example.com"}}'
    if invalid == "expired":
        cookie = cipher.encrypt_at_time(data, int(time.time()) - SESSION_MAX_AGE - 1)
    elif invalid == "wrong-key":
        cookie = EncryptedSessionMiddleware(app, "other-secret").cipher.encrypt(data)
    elif invalid == "not-dict":
        cookie = cipher.encrypt(b"[]")
    elif invalid == "invalid-json":
        cookie = cipher.encrypt(b"not-json")
    elif invalid == "legacy":
        cookie = b"eyJ1c2VyIjp7fX0.old-signature"
    else:
        cookie = cipher.encrypt(data)
        cookie = cookie[:40] + (b"A" if cookie[40:41] != b"A" else b"B") + cookie[41:]
    with TestClient(app) as client:
        client.cookies.set("session", cookie.decode())
        assert client.get("/").json() == {}


@pytest.mark.parametrize("https_only", [False, True])
def test_session_confidentiality_and_cookie_flags(https_only):
    app = session_app(https_only=https_only)
    with TestClient(app, base_url="https://testserver" if https_only else "http://testserver") as client:
        response = client.get("/write")
        header = response.headers["set-cookie"]
        assert "HttpOnly" in header and "SameSite=lax" in header and "Path=/" in header
        assert ("; Secure" in header) is https_only
        cookie = client.cookies.get("session")
        assert cookie is not None
        assert "private-token" not in cookie
        cipher = EncryptedSessionMiddleware(app, "test-secret").cipher
        assert json.loads(cipher.decrypt(cookie.encode())) == {"refresh_token": "private-token"}
        response = client.get("/")
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {"refresh_token": "private-token"}
        assert "set-cookie" not in response.headers
