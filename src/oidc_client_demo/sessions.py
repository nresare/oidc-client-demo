# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

import base64
import json

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SESSION_MAX_AGE = 14 * 24 * 60 * 60


class EncryptedSessionMiddleware:
    """Authenticated, encrypted cookie sessions using the configured random secret."""

    def __init__(self, app: ASGIApp, secret_key: str, https_only: bool = False) -> None:
        self.app = app
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"oidc-client-demo/session/v1").derive(
            secret_key.encode("utf-8")
        )
        self.cipher = Fernet(base64.urlsafe_b64encode(key))
        self.flags = "; Path=/; HttpOnly; SameSite=lax" + ("; Secure" if https_only else "")

    def cookie_header(self, session: dict) -> str:
        data = json.dumps(session, separators=(",", ":")).encode("utf-8")
        encrypted = self.cipher.encrypt(data).decode("ascii")
        return f"session={encrypted}; Max-Age={SESSION_MAX_AGE}{self.flags}"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        cookie = HTTPConnection(scope).cookies.get("session")
        session = {}
        if cookie and len(cookie) <= 4096:
            try:
                decoded = json.loads(self.cipher.decrypt(cookie.encode("utf-8"), ttl=SESSION_MAX_AGE))
                if isinstance(decoded, dict):
                    session = decoded
            except (InvalidToken, ValueError, UnicodeError):
                pass
        scope["session"] = session
        initial = json.dumps(session, sort_keys=True)
        rejected = False

        async def send_wrapper(message: Message) -> None:
            nonlocal rejected
            if rejected:
                return
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.add_vary_header("Cookie")
                current = scope["session"]
                if current or cookie:
                    headers["cache-control"] = "no-store"
                if json.dumps(current, sort_keys=True) != initial:
                    if current:
                        header = self.cookie_header(current)
                        if len(header.encode("ascii")) > 4096:
                            # Never send a cookie that browsers may silently discard.
                            rejected = True
                            response = Response(
                                "Session data is too large for a cookie. Sign in again with fewer claims or a smaller refresh token.",
                                status_code=400,
                                media_type="text/plain",
                            )
                            response.headers.append("set-cookie", f"session=null; Max-Age=0{self.flags}")
                            response.headers["cache-control"] = "no-store"
                            await response(scope, receive, send)
                            return
                    else:
                        header = f"session=null; Max-Age=0{self.flags}"
                    headers.append("set-cookie", header)
            await send(message)

        await self.app(scope, receive, send_wrapper)
