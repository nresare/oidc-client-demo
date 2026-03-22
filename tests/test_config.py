import tempfile
from pathlib import Path

import pytest

from website_with_login.config import Config, load_config


def test_load_config_missing_file():
    with pytest.raises(FileNotFoundError, match="Config file not found"):
        load_config("/nonexistent/config.toml")


def test_load_config_defaults():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[oidc]
issuer = "http://localhost:9000"
client_id = "my-client"
""")
        config_path = f.name

    try:
        config = load_config(config_path)
        assert isinstance(config, Config)
        assert config.app.base_url == "http://localhost:8080"
        assert config.app.secret_key == "change-me-for-real-use"
        assert config.oidc.server_metadata_url == "http://localhost:9000/.well-known/openid-configuration"
        assert config.oidc.scopes == ["openid", "profile", "email"]
    finally:
        Path(config_path).unlink()


def test_load_config_requires_oidc_fields():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[oidc]
issuer = "http://localhost:9000"
""")
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="Missing required OIDC configuration fields: client_id"):
            load_config(config_path)
    finally:
        Path(config_path).unlink()
