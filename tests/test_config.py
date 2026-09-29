import pytest

from oidc_client_demo.config import Config, load_config


def write_config(tmp_path, app_config='secret_key_path = "session-key"'):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'[app]\n{app_config}\n\n[oidc]\nissuer = "http://localhost:9000"\nclient_id = "my-client"\n'
    )
    return str(config_path)


def test_load_config_missing_file():
    with pytest.raises(FileNotFoundError, match="Config file not found"):
        load_config("/nonexistent/config.toml")


def test_load_config_defaults(tmp_path):
    (tmp_path / "session-key").write_text("test-secret\n")
    config = load_config(write_config(tmp_path))
    assert isinstance(config, Config)
    assert config.app.base_url == "http://localhost:8080"
    assert config.app.secret_key == "test-secret"
    assert config.oidc.server_metadata_url == "http://localhost:9000/.well-known/openid-configuration"
    assert config.oidc.scopes == ["openid", "profile", "email"]


def test_load_config_absolute_secret_path(tmp_path):
    secret_path = tmp_path / "mounted-key"
    secret_path.write_text("random-secret")
    config = load_config(write_config(tmp_path, f'secret_key_path = "{secret_path}"'))
    assert config.app.secret_key == "random-secret"


@pytest.mark.parametrize("app_config", ["", 'secret_key_path = ""', 'secret_key_path = "  "', "secret_key_path = 123"])
def test_load_config_requires_secret_path(tmp_path, app_config):
    with pytest.raises(ValueError, match="app.secret_key_path"):
        load_config(write_config(tmp_path, app_config))


def test_load_config_rejects_inline_secret(tmp_path):
    with pytest.raises(ValueError, match="no longer supported"):
        load_config(write_config(tmp_path, 'secret_key = "old-secret"'))


def test_load_config_missing_secret_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(write_config(tmp_path))


@pytest.mark.parametrize("contents", ["", " \n\t"])
def test_load_config_empty_secret_file(tmp_path, contents):
    (tmp_path / "session-key").write_text(contents)
    with pytest.raises(ValueError, match="Secret key file is empty"):
        load_config(write_config(tmp_path))


def test_load_config_requires_oidc_fields(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text('[oidc]\nissuer = "http://localhost:9000"\n')
    with pytest.raises(ValueError, match="Missing required OIDC configuration fields: client_id"):
        load_config(str(config_path))


def test_load_config_reads_oidc_client_secret_from_file(tmp_path):
    (tmp_path / "session-key").write_text("test-secret")
    (tmp_path / "client-secret").write_text("entra-secret\n")
    config_path = write_config(tmp_path)
    with open(config_path, "a") as config_file:
        config_file.write('client_secret_path = "client-secret"\n')
    assert load_config(config_path).oidc.client_secret == "entra-secret"


@pytest.mark.parametrize(
    ("extra_config", "unknown_parameter"),
    [
        ('\nclient_seret_path = "/secret/client-secret"', "oidc.client_seret_path"),
        ('\n[extra]\nvalue = "ignored"', "extra"),
    ],
)
def test_load_config_rejects_unknown_parameters(tmp_path, extra_config, unknown_parameter):
    config_path = write_config(tmp_path)
    with open(config_path, "a") as config_file:
        config_file.write(extra_config)

    with pytest.raises(ValueError) as exc_info:
        load_config(config_path)
    assert str(exc_info.value) == f"Unknown configuration parameter(s): {unknown_parameter}"


def test_load_config_rejects_unknown_app_parameter(tmp_path):
    config_path = write_config(tmp_path, 'secret_key_path = "session-key"\nsecreet_key_path = "session-key"')

    with pytest.raises(ValueError) as exc_info:
        load_config(config_path)
    assert str(exc_info.value) == "Unknown configuration parameter(s): app.secreet_key_path"
