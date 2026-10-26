"""Diagnostic validation of JWT access tokens for an explicitly configured API."""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, cast

import httpx2
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, KeySetSerialization

from oidc_client_demo.config import OidcConfig

# Never accept symmetric algorithms or keys/URLs supplied by the token.
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]
ENTRA_ISSUER = re.compile(r"https://login\.microsoftonline\.com/([0-9a-fA-F-]{36})/v2\.0/?")


@dataclass
class AccessTokenInspection:
    status: str
    detail: str
    claims: dict[str, Any] = field(default_factory=dict)
    issuer: str = ""
    audiences: list[str] = field(default_factory=list)


def decode_claims(access_token: str) -> dict[str, Any]:
    """Decode only for display and version selection; these claims are untrusted."""
    parts = access_token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a signed JWT")
    payload = parts[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    if not isinstance(claims, dict):
        raise TypeError("Not a claims object")
    return claims


def validate_access_token(
    access_token: str,
    jwks: dict[str, Any],
    issuer: str,
    audiences: list[str],
    required_scopes: list[str],
) -> None:
    token = jwt.decode(access_token, KeySet.import_key_set(cast(KeySetSerialization, jwks)), algorithms=ALGORITHMS)
    jwt.JWTClaimsRegistry(
        iss={"essential": True, "value": issuer},
        aud={"essential": True, "values": audiences},
        exp={"essential": True},
        sub={"essential": True},
    ).validate(token.claims)
    scopes = token.claims.get("scp", "")
    if required_scopes and (not isinstance(scopes, str) or not set(required_scopes).issubset(scopes.split())):
        raise ValueError("Required delegated scopes are missing")


async def inspect_access_token(
    access_token: str | None, config: OidcConfig, metadata: dict[str, Any]
) -> AccessTokenInspection:
    if not access_token:
        return AccessTokenInspection("Missing", "No access token is available for this session.")
    try:
        claims = decode_claims(access_token)
    except (ValueError, TypeError, UnicodeError):
        return AccessTokenInspection(
            "Not validated", "The access token is opaque, encrypted, or not a readable signed JWT."
        )

    issuer = config.issuer.rstrip("/")
    inspection = AccessTokenInspection(
        "Not validated",
        "Configure oidc.access-token-audiences to enable validation.",
        claims,
        issuer,
        config.access_token_audiences,
    )
    if not config.access_token_audiences:
        return inspection

    # Entra's access-token version is selected by the resource, independently of
    # the OIDC endpoint used to sign in. Both issuers are pinned to the configured
    # tenant. The unverified version can only select between these trusted paths.
    tenant_match = ENTRA_ISSUER.fullmatch(config.issuer)
    legacy_metadata_url = None
    if tenant_match:
        tenant = tenant_match[1]
        if claims.get("ver") == "1.0":
            issuer = f"https://sts.windows.net/{tenant}/"
            legacy_metadata_url = f"https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration"
        elif claims.get("ver") != "2.0":
            inspection.status = "Invalid"
            inspection.detail = "Unsupported Entra access-token version; expected 1.0 or 2.0."
            return inspection
    else:
        issuer = config.issuer
    inspection.issuer = issuer

    try:
        async with httpx2.AsyncClient(timeout=10, http2=True) as client:
            if legacy_metadata_url:
                response = await client.get(legacy_metadata_url)
                response.raise_for_status()
                metadata = response.json()
                if not isinstance(metadata, dict) or metadata.get("issuer") != issuer:
                    inspection.detail = "Provider metadata does not match the expected issuer."
                    return inspection
            jwks_uri = metadata.get("jwks_uri")
            if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
                inspection.detail = "Provider metadata has no HTTPS signing-key endpoint."
                return inspection
            response = await client.get(jwks_uri)
            response.raise_for_status()
            jwks = response.json()
    except (httpx2.HTTPError, ValueError):
        inspection.detail = "Unable to retrieve provider signing keys or metadata. Try again."
        return inspection

    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        inspection.detail = "The provider returned an invalid signing-key set."
        return inspection
    try:
        validate_access_token(
            access_token, jwks, issuer, config.access_token_audiences, config.access_token_required_scopes
        )
    except JoseError as exc:
        inspection.status = "Invalid"
        claim = getattr(exc, "claim", None)
        inspection.detail = f"JWT validation failed: {exc.error}" + (f" ({claim})." if claim else ".")
    except (ValueError, TypeError, KeyError):
        inspection.status = "Invalid"
        inspection.detail = "Invalid JWT, signing keys, or missing required delegated scopes."
    else:
        inspection.status = "Valid"
        inspection.detail = "Signature, issuer, audience, lifetime, and configured delegated scopes passed validation."
    return inspection
