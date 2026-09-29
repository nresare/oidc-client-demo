# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2

GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"


def token_expiry(token: dict[str, Any]) -> datetime | None:
    expires_at = token.get("expires_at")
    if isinstance(expires_at, (int, float)):
        return datetime.fromtimestamp(expires_at, UTC)
    expires_in = token.get("expires_in")
    if isinstance(expires_in, (int, float)):
        return datetime.now(UTC) + timedelta(seconds=expires_in)
    return None


@dataclass
class TokenRecord:
    access_token: str | None
    refresh_token: str | None
    expires_at: datetime | None
    scope: str | None
    last_refresh: str | None = None
    last_graph: str | None = None

    @classmethod
    def from_response(cls, token: dict[str, Any]) -> "TokenRecord":
        return cls(
            access_token=token.get("access_token"),
            refresh_token=token.get("refresh_token"),
            expires_at=token_expiry(token),
            scope=token.get("scope"),
        )


async def refresh_access_token(
    token_endpoint: str, client_id: str, client_secret: str | None, refresh_token: str
) -> dict[str, Any]:
    data = {"grant_type": "refresh_token", "client_id": client_id, "refresh_token": refresh_token}
    if client_secret:
        data["client_secret"] = client_secret
    async with httpx2.AsyncClient(timeout=10) as client:
        response = await client.post(token_endpoint, data=data)
    try:
        result = response.json()
    except ValueError:
        return {"error": f"Token endpoint returned HTTP {response.status_code} without JSON"}
    if not isinstance(result, dict):
        return {"error": f"Token endpoint returned HTTP {response.status_code} without an object"}
    if response.status_code >= 400:
        # Error descriptions can contain tenant details, so display only the protocol error code.
        error = str(result.get("error", f"HTTP {response.status_code}"))
        codes = result.get("error_codes")
        if isinstance(codes, list) and codes and isinstance(codes[0], int):
            error += f" (AADSTS{codes[0]})"
        return {"error": error}
    return result


async def call_graph_me(access_token: str) -> int:
    async with httpx2.AsyncClient(timeout=10) as client:
        response = await client.get(GRAPH_ME_URL, headers={"Authorization": f"Bearer {access_token}"})
    return response.status_code
