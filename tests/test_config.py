import pytest

from oidc_client_demo.config import Config, load_config


def write_config(tmp_path, app_config='secret-key-path = "session-key"'):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'[app]\n{app_config}\n\n[oidc]\nissuer = "http://localhost:9000"\nclient-id = "my-client"\n'
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


@pytest.mark.parametrize("name", ["access-token-audiences", "access-token-required-scopes"])
@pytest.mark.parametrize("value", ['"not-a-list"', '[""]', "[123]"])
def test_load_config_rejects_invalid_access_token_settings(tmp_path, name, value):
    (tmp_path / "session-key").write_text("test-secret")
    config_path = write_config(tmp_path)
    with open(config_path, "a") as config_file:
        config_file.write(f"{name} = {value}\n")
    with pytest.raises(ValueError, match=name):
        load_config(config_path)


def test_load_config_reads_access_token_settings(tmp_path):
    (tmp_path / "session-key").write_text("test-secret")
    config_path = write_config(tmp_path)
    with open(config_path, "a") as config_file:
        config_file.write('access-token-audiences = ["api-id", "api://api-id"]\n')
        config_file.write('access-token-required-scopes = ["Full"]\n')
    config = load_config(config_path)
    assert config.oidc.access_token_audiences == ["api-id", "api://api-id"]
    assert config.oidc.access_token_required_scopes == ["Full"]


def test_load_config_absolute_secret_path(tmp_path):
    secret_path = tmp_path / "mounted-key"
    secret_path.write_text("random-secret")
    config = load_config(write_config(tmp_path, f'secret-key-path = "{secret_path}"'))
    assert config.app.secret_key == "random-secret"


@pytest.mark.parametrize("app_config", ["", 'secret-key-path = ""', 'secret-key-path = "  "', "secret-key-path = 123"])
def test_load_config_requires_secret_path(tmp_path, app_config):
    with pytest.raises(ValueError, match="app.secret-key-path"):
        load_config(write_config(tmp_path, app_config))


def test_load_config_rejects_inline_secret(tmp_path):
    with pytest.raises(ValueError, match="no longer supported"):
        load_config(write_config(tmp_path, 'secret-key = "old-secret"'))


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
    with pytest.raises(ValueError, match="Missing required OIDC configuration fields: client-id"):
        load_config(str(config_path))


def test_load_config_reads_oidc_client_secret_from_file(tmp_path):
    (tmp_path / "session-key").write_text("test-secret")
    (tmp_path / "client-secret").write_text("client-secret-value\n")
    config_path = write_config(tmp_path)
    with open(config_path, "a") as config_file:
        config_file.write('client-secret-path = "client-secret"\n')
    assert load_config(config_path).oidc.client_secret == "client-secret-value"


@pytest.mark.parametrize(
    ("extra_config", "unknown_parameter"),
    [
        ('\nclient-seret-path = "/secret/client-secret"', "oidc.client-seret-path"),
        ('\n[extra]\nvalue = "ignored"', "extra"),
        ('\nclient_id = "old-client"', "oidc.client_id"),
        ('\n[otel]\nendpoint = "http://tempo:4318/v1/traces"', "otel"),
        ('\n[traces]\nservice_name = "demo"', "traces.service_name"),
    ],
)
def test_load_config_rejects_unknown_parameters(tmp_path, extra_config, unknown_parameter):
    config_path = write_config(tmp_path)
    with open(config_path, "a") as config_file:
        config_file.write(extra_config)

    with pytest.raises(ValueError) as exc_info:
        load_config(config_path)
    assert str(exc_info.value) == f"Unknown configuration parameter(s): {unknown_parameter}"


@pytest.mark.parametrize("name", ["secreet-key-path", "secret_key_path", "base_url", "tls_cert_path", "tls_key_path"])
def test_load_config_rejects_unknown_app_parameter(tmp_path, name):
    config_path = write_config(tmp_path, f'secret-key-path = "session-key"\n{name} = "session-key"')

    with pytest.raises(ValueError) as exc_info:
        load_config(config_path)
    assert str(exc_info.value) == f"Unknown configuration parameter(s): app.{name}"


def test_load_config_traces(tmp_path):
    (tmp_path / "session-key").write_text("test-secret")
    path = write_config(tmp_path)
    with open(path, "a") as f:
        f.write('\n[traces]\nendpoint = "http://tempo:4318/v1/traces"\n')
    config = load_config(path)
    assert config.traces is not None
    assert config.traces.endpoint == "http://tempo:4318/v1/traces"
    assert config.traces.service_name == "oidc-client-demo"


@pytest.mark.parametrize("endpoint", ['""', "123", '"grpc://tempo:4317"'])
def test_load_config_invalid_traces(tmp_path, endpoint):
    (tmp_path / "session-key").write_text("test-secret")
    path = write_config(tmp_path)
    with open(path, "a") as f:
        f.write(f"\n[traces]\nendpoint = {endpoint}\n")
    with pytest.raises(ValueError, match="traces.endpoint"):
        load_config(path)


@pytest.mark.parametrize("absolute", [False, True])
def test_load_config_tls_paths(tmp_path, absolute):
    (tmp_path / "session-key").write_text("test-secret")
    cert = str(tmp_path / "cert.pem") if absolute else "cert.pem"
    key = str(tmp_path / "key.pem") if absolute else "key.pem"
    config = load_config(
        write_config(tmp_path, f'secret-key-path = "session-key"\ntls-cert-path = "{cert}"\ntls-key-path = "{key}"')
    )
    assert config.app.tls_cert_path == str(tmp_path / "cert.pem")
    assert config.app.tls_key_path == str(tmp_path / "key.pem")


@pytest.mark.parametrize(
    "tls_config",
    [
        'tls-cert-path = "cert.pem"',
        'tls-key-path = "key.pem"',
        'tls-cert-path = ""\ntls-key-path = "key.pem"',
        'tls-cert-path = "cert.pem"\ntls-key-path = "  "',
        'tls-cert-path = 123\ntls-key-path = "key.pem"',
        'tls-cert-path = "cert.pem"\ntls-key-path = false',
    ],
)
def test_load_config_requires_valid_tls_pair(tmp_path, tls_config):
    (tmp_path / "session-key").write_text("test-secret")
    with pytest.raises(ValueError, match="TLS requires both"):
        load_config(write_config(tmp_path, f'secret-key-path = "session-key"\n{tls_config}'))


@pytest.mark.parametrize("value", ['"/healthz"', "[123]", '["healthz"]', '["/healthz?x=1"]', '["/healthz#x"]'])
def test_load_config_rejects_invalid_excluded_paths(tmp_path, value):
    (tmp_path / "session-key").write_text("test-secret")
    path = write_config(tmp_path)
    with open(path, "a") as f:
        f.write(f'\n[traces]\nendpoint = "http://tempo:4318/v1/traces"\nexcluded-paths = {value}\n')
    with pytest.raises(ValueError, match="traces.excluded-paths"):
        load_config(path)
