# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_PARAMETERS = {
    # Keep deprecated names here so their existing, more specific errors still apply.
    "app": {"secret_key", "secret_key_path", "base_url"},
    "oidc": {"issuer", "client_id", "client_secret", "client_secret_path", "scopes"},
}


@dataclass
class AppConfig:
    secret_key: str
    base_url: str = "http://localhost:8080"


@dataclass
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str | None = None
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])

    @property
    def server_metadata_url(self) -> str:
        return f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"


@dataclass
class Config:
    app: AppConfig
    oidc: OidcConfig


def load_config(config_path: str) -> Config:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    logger.info("Loading config from: %s", config_path)
    with open(path, "rb") as f:
        data = tomllib.load(f)

    unknown = []
    for section, values in data.items():
        if section not in CONFIG_PARAMETERS:
            unknown.append(section)
        elif isinstance(values, dict):
            unknown.extend(f"{section}.{key}" for key in values if key not in CONFIG_PARAMETERS[section])
    if unknown:
        raise ValueError(f"Unknown configuration parameter(s): {', '.join(sorted(unknown))}")

    app_data = data.get("app", {})
    oidc_data = data.get("oidc", {})

    required_oidc_fields = ["issuer", "client_id"]
    missing_fields = [field for field in required_oidc_fields if not oidc_data.get(field)]
    if missing_fields:
        raise ValueError(f"Missing required OIDC configuration fields: {', '.join(missing_fields)}")

    if "secret_key" in app_data:
        raise ValueError("app.secret_key is no longer supported; use app.secret_key_path")
    secret_key_path = app_data.get("secret_key_path")
    if not isinstance(secret_key_path, str) or not secret_key_path.strip():
        raise ValueError("Missing or invalid app.secret_key_path")
    secret_path = Path(secret_key_path)
    if not secret_path.is_absolute():
        secret_path = path.parent / secret_path
    secret_key = secret_path.read_text(encoding="utf-8").strip()
    if not secret_key:
        raise ValueError(f"Secret key file is empty: {secret_path}")

    client_secret = None
    if "client_secret" in oidc_data:
        raise ValueError("oidc.client_secret is not supported; use oidc.client_secret_path")
    client_secret_path = oidc_data.get("client_secret_path")
    if client_secret_path is not None:
        if not isinstance(client_secret_path, str) or not client_secret_path.strip():
            raise ValueError("Invalid oidc.client_secret_path")
        client_secret_file = Path(client_secret_path)
        if not client_secret_file.is_absolute():
            client_secret_file = path.parent / client_secret_file
        client_secret = client_secret_file.read_text(encoding="utf-8").strip()
        if not client_secret:
            raise ValueError(f"Client secret file is empty: {client_secret_file}")

    return Config(
        app=AppConfig(
            secret_key=secret_key,
            base_url=app_data.get("base_url", "http://localhost:8080"),
        ),
        oidc=OidcConfig(
            issuer=oidc_data["issuer"],
            client_id=oidc_data["client_id"],
            client_secret=client_secret,
            scopes=oidc_data.get("scopes", ["openid", "profile", "email"]),
        ),
    )
