import time

import httpx2
import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from oidc_client_demo import access_tokens
from oidc_client_demo.config import OidcConfig

TENANT = "1b5955bf-2426-4ced-8412-9fe81bb8bca4"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
AUDIENCE = "0816f759-d89d-4319-a8d7-d88b5d751dc9"


@pytest.fixture(scope="module")
def signing_key():
    return RSAKey.generate_key(2048, parameters={"kid": "test-key"})


def token_claims(**overrides):
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "scp": "Full",
        "ver": "2.0",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        **overrides,
    }


def signed_token(key, claims):
    return jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, key)


def mock_provider(monkeypatch, signing_key, *, fail=False):
    urls = []

    def respond(request):
        urls.append(str(request.url))
        if fail:
            return httpx2.Response(503)
        if request.url.path.endswith("openid-configuration"):
            return httpx2.Response(
                200,
                json={
                    "issuer": f"https://sts.windows.net/{TENANT}/",
                    "jwks_uri": "https://keys.example/v1",
                },
            )
        return httpx2.Response(200, json={"keys": [signing_key.as_dict(private=False)]})

    real_client = httpx2.AsyncClient
    monkeypatch.setattr(
        access_tokens.httpx2,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx2.MockTransport(respond), **kwargs),
    )
    return urls


@pytest.mark.anyio
@pytest.mark.parametrize("version", ["1.0", "2.0"])
async def test_entra_versions_use_trusted_issuer_and_discovery(monkeypatch, signing_key, version):
    urls = mock_provider(monkeypatch, signing_key)
    issuer = f"https://sts.windows.net/{TENANT}/" if version == "1.0" else ISSUER
    audience = f"api://{AUDIENCE}" if version == "1.0" else AUDIENCE
    config = OidcConfig(
        ISSUER,
        "demo",
        access_token_audiences=[AUDIENCE, f"api://{AUDIENCE}"],
        access_token_required_scopes=["Full"],
    )
    result = await access_tokens.inspect_access_token(
        signed_token(signing_key, token_claims(ver=version, iss=issuer, aud=audience)),
        config,
        {"jwks_uri": "https://keys.example/v2"},
    )
    assert result.status == "Valid"
    assert result.issuer == issuer
    assert result.claims["scp"] == "Full"
    if version == "1.0":
        assert urls == [
            f"https://login.microsoftonline.com/{TENANT}/.well-known/openid-configuration",
            "https://keys.example/v1",
        ]
    else:
        assert urls == ["https://keys.example/v2"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.example"},
        {"aud": "another-api"},
        {"exp": 1},
        {"exp": None},
        {"nbf": 9999999999},
        {"iat": 9999999999},
        {"scp": "OtherFull"},
        {"scp": ["Full"]},
        {"ver": "3.0"},
    ],
)
async def test_invalid_tokens_are_never_reported_valid(monkeypatch, signing_key, overrides):
    mock_provider(monkeypatch, signing_key)
    result = await access_tokens.inspect_access_token(
        signed_token(signing_key, token_claims(**overrides)),
        OidcConfig(ISSUER, "demo", access_token_audiences=[AUDIENCE], access_token_required_scopes=["Full"]),
        {"jwks_uri": "https://keys.example/v2"},
    )
    assert result.status == "Invalid"


@pytest.mark.anyio
async def test_invalid_signature(monkeypatch, signing_key):
    mock_provider(monkeypatch, signing_key)
    other_key = RSAKey.generate_key(2048, parameters={"kid": "test-key"})
    result = await access_tokens.inspect_access_token(
        signed_token(other_key, token_claims()),
        OidcConfig(ISSUER, "demo", access_token_audiences=[AUDIENCE]),
        {"jwks_uri": "https://keys.example/v2"},
    )
    assert result.status == "Invalid"


@pytest.mark.anyio
async def test_provider_failure_is_not_a_valid_token(monkeypatch, signing_key):
    mock_provider(monkeypatch, signing_key, fail=True)
    result = await access_tokens.inspect_access_token(
        signed_token(signing_key, token_claims()),
        OidcConfig(ISSUER, "demo", access_token_audiences=[AUDIENCE]),
        {"jwks_uri": "https://keys.example/v2"},
    )
    assert result.status == "Not validated"
    assert result.claims["sub"] == "alice"


@pytest.mark.anyio
@pytest.mark.parametrize("token,expected", [(None, "Missing"), ("opaque-token", "Not validated")])
async def test_missing_and_opaque_tokens(token, expected):
    result = await access_tokens.inspect_access_token(token, OidcConfig(ISSUER, "demo"), {})
    assert result.status == expected
    assert result.claims == {}


@pytest.mark.anyio
async def test_no_audience_displays_claims_without_claiming_validation(signing_key):
    result = await access_tokens.inspect_access_token(
        signed_token(signing_key, token_claims()),
        OidcConfig(ISSUER, "demo"),
        {},
    )
    assert result.status == "Not validated"
    assert result.claims["scp"] == "Full"
