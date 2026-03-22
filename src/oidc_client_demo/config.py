# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AppConfig:
    secret_key: str = "change-me-for-real-use"
    base_url: str = "http://localhost:8080"


@dataclass
class OidcConfig:
    issuer: str
    client_id: str
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

    app_data = data.get("app", {})
    oidc_data = data.get("oidc", {})

    required_oidc_fields = ["issuer", "client_id"]
    missing_fields = [field for field in required_oidc_fields if not oidc_data.get(field)]
    if missing_fields:
        raise ValueError(f"Missing required OIDC configuration fields: {', '.join(missing_fields)}")

    return Config(
        app=AppConfig(
            secret_key=app_data.get("secret_key", "change-me-for-real-use"),
            base_url=app_data.get("base_url", "http://localhost:8080"),
        ),
        oidc=OidcConfig(
            issuer=oidc_data["issuer"],
            client_id=oidc_data["client_id"],
            scopes=oidc_data.get("scopes", ["openid", "profile", "email"]),
        ),
    )
