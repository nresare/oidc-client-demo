from unittest.mock import AsyncMock

import pytest

from oidc_client_demo import tokens


@pytest.mark.anyio
async def test_refresh_request_uses_refresh_grant_and_client_secret(monkeypatch):
    posted = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"access_token": "new-access", "refresh_token": "new-refresh"}

    class FakeClient:
        def __init__(self, timeout):
            assert timeout == 10

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, data):
            posted.update(url=url, data=data)
            return FakeResponse()

    monkeypatch.setattr(tokens.httpx2, "AsyncClient", FakeClient)
    result = await tokens.refresh_access_token("https://idp.example/token", "client-id", "secret", "old-refresh")

    assert posted == {
        "url": "https://idp.example/token",
        "data": {
            "grant_type": "refresh_token",
            "client_id": "client-id",
            "client_secret": "secret",
            "refresh_token": "old-refresh",
        },
    }
    assert result["refresh_token"] == "new-refresh"


@pytest.mark.anyio
async def test_graph_request_uses_access_token(monkeypatch):
    get = AsyncMock()
    get.return_value.status_code = 200

    class FakeClient:
        def __init__(self, timeout):
            assert timeout == 10

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url, headers):
            return await get(url, headers=headers)

    monkeypatch.setattr(tokens.httpx2, "AsyncClient", FakeClient)
    assert await tokens.call_graph_me("access-value") == 200
    get.assert_awaited_once_with(tokens.GRAPH_ME_URL, headers={"Authorization": "Bearer access-value"})


@pytest.mark.anyio
async def test_refresh_error_shows_code_without_description(monkeypatch):
    class FakeResponse:
        status_code = 400

        def json(self):
            return {"error": "invalid_grant", "error_codes": [700082], "error_description": "private details"}

    class FakeClient:
        def __init__(self, timeout):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, data):
            return FakeResponse()

    monkeypatch.setattr(tokens.httpx2, "AsyncClient", FakeClient)
    result = await tokens.refresh_access_token("https://idp.example/token", "client-id", None, "old-refresh")
    assert result == {"error": "invalid_grant (AADSTS700082)"}
