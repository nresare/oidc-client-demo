# oidc-client-demo

This repo contains a web app intended to illustrate how to authenticate with OpenID Connect.
It is somewhat inspired by https://github.com/noa-portswigger/flask-lab

## Features

- TOML-based configuration loading
- Uses Hypercorn
- OIDC login, callback, protected profile page, and logout
- PKCE lets the identity provider verify that the client exchanging the authorization code initiated the sign-in
- Token status and manual refresh on the profile page

## Configuration

Copy `config.toml.example` to `config.toml` and update the values for your identity provider.
Configuration keys use kebab-case, and optional request tracing is configured in `[traces]`.
Unknown configuration sections and parameters cause startup to fail with their names in the error.
The identity provider you use needs to support PKCE which enables integration without a
client secret.

You need to register this app with the OpenID connect identity provider you are using.
Use the path /auth/callback on this service when configuring the callback url for your client registration

## Local Development

```bash
uv sync
umask 077
uv run python -c 'import secrets; print(secrets.token_urlsafe(32))' > session-key
cp config.toml.example config.toml
uv run oidc-client-demo
```

The app listens on port `8080`.

## HTTPS and HTTP/2

To enable TLS on the listener, set both PEM file paths in `[app]`:

```toml
[app]
secret-key-path = "session-key"
base-url = "https://demo.example.com"
tls-cert-path = "tls/cert.pem"
tls-key-path = "tls/key.pem"
```

Relative paths are resolved from the configuration file's directory. Supply a PEM
certificate (including any intermediate certificates) and its matching unencrypted
PEM private key. Missing, unreadable, invalid, or mismatched files prevent server
startup. Restart the app after replacing the files to load the new certificate.

With both paths configured, port `8443` serves HTTPS and advertises `h2` and
`http/1.1` through ALPN. Configure the terminating proxy to connect to the workload
using TLS with HTTP/2, trust the certificate's issuer, and use a server name that
matches the certificate. Health checks must also use HTTPS. Omit both paths to
keep the plain HTTP listener.

`app.base-url` remains the public URL used for OIDC redirects and session cookie
settings; it can differ from the proxy's upstream address. For direct local HTTPS,
set it to `https://localhost:8443` and register the corresponding callback URL.

## Refresh tokens

The profile page shows whether access and refresh tokens were issued, the access-token
expiry, and the granted scopes. Select **Refresh now** to request a new access token
from the identity provider without a browser redirect. The result reports whether
the access token changed and whether a replacement refresh token was received.

To request refresh tokens, add `"offline_access"` to `oidc.scopes`, for example
`["openid", "profile", "email", "offline_access"]`, and enable refresh-token issuance
for your client at the identity provider if required. If your provider requires a
client secret, save it in a local `client-secret` file (mode `0600`) beside
`config.toml` and set `oidc.client-secret-path = "client-secret"`.

The app never displays token values. Session data, including the refresh token,
is stored in an authenticated, encrypted browser cookie using a key derived from
`app.secret-key-path`. The cookie is HttpOnly, uses SameSite=Lax, and is marked
Secure when `app.base-url` uses HTTPS. Sessions expire after 14 days without a
session update. Refresh-token rotation updates the cookie; if no replacement is
issued, the existing refresh token is retained.

Access tokens and their metadata are cached in process memory. If the cache is
lost after a restart or a request reaches another worker, opening the profile
page uses the refresh token to obtain a new access token. Workers must share the
same session key. Without a refresh token, sign in again to restore the access
token. Concurrent refreshes across workers or browser tabs may require signing
in again with providers that reject reuse of rotated refresh tokens.

Refresh tokens can vary in size by provider. The complete encrypted session
cookie must fit within 4096 bytes, including its attributes; oversized sessions
return an error and clear the cookie. Access and ID tokens are never stored in
the session cookie. Signing out clears the cookie and this worker's cached access
token, but does not revoke tokens at the identity provider or invalidate a copied
cookie. A refresh failure displays the protocol error code and leaves the option
to sign in again.

Set `app.secret-key-path` to a UTF-8 file containing the session encryption secret.
Relative paths are resolved from the configuration file's directory. Leading and
trailing whitespace is stripped; missing or empty files prevent startup. Inline
`app.secret-key` values are no longer supported. Keep the key stable across restarts
to preserve sessions; replacing it invalidates existing sessions.

The deployment manifest requests `random-secret = "session-key"`, which mounts the
generated key at `/random-secrets/session-key`. The deployment configuration uses
that path. It also sets `tls = true` in the website block, which creates a
certificate from the `cluster-local` ClusterIssuer and mounts its Secret at `/tls`.
The app reads `/tls/tls.crt` and `/tls/tls.key`. The generated BackendTLSPolicy
validates the service certificate against the `cluster-local-ca` ConfigMap,
distributed by trust-manager to namespaces labeled `trust: cluster-local`.
The website block adds that namespace label and switches the service and health
check to HTTPS. This requires the website plugin update in
[system PR #62](https://github.com/nresare/system/pull/62) before deployment.

## Access token inspection

The profile page displays access-token validation results and JSON claims when
the provider returns a readable signed JWT. Configure `oidc.access-token-audiences`
with the intended API's audience identifiers to enable validation. Optionally set
`oidc.access-token-required-scopes` to require delegated permissions in `scp`:

```toml
access-token-audiences = ["<api-application-id>", "api://<api-application-id>"]
access-token-required-scopes = ["Full"]
```

Validation checks the signature using the provider's published signing keys,
the issuer, audience, expiry, any not-before/issued-at timestamps, and configured
delegated scopes. The audience is the target API, not this demo's client ID.
For Entra, configure a tenant-GUID issuer such as
`https://login.microsoftonline.com/<tenant-id>/v2.0`. The demo handles both v1
and v2 access tokens, selecting the corresponding discovery endpoint and expected
issuer for that same tenant. No Entra token-version manifest change is required.
Register the demo's callback as a Web redirect URI and configure its client secret;
PKCE does not replace client authentication for Entra confidential web clients.

Opaque/encrypted tokens and tokens without configured audiences are reported as
not validated. Decodable claims from tokens that have not passed validation are
explicitly labeled unverified. Claims are diagnostic information for the API you
configure; they do not change sign-in or implement the API's ownership or role
policies. Raw tokens are never displayed. Validation fetches signing keys on each
profile view and checks the current token again after refresh, including expiry.

## Request tracing with Tempo

To enable tracing, add this section to your configuration:

```toml
[traces]
endpoint = "http://localhost:4318/v1/traces"
service-name = "oidc-client-demo"
excluded-paths = ["/healthz"]
```

Use the full OTLP/HTTP traces URL, including `/v1/traces`, for your Tempo or
collector receiver (not the gRPC port 4317). The service name is optional and
defaults to `oidc-client-demo`. Omit `[traces]` to disable tracing.

`excluded-paths` skips tracing for exact URL paths, regardless of method or query
string. It defaults to an empty list. The deployment excludes `/healthz`.

Each remaining HTTP request creates one server span with its method, path, status
code and duration. Span names use the method and matched route template, such as
`GET /profile` or `GET /users/{id}`, and include the `http.route` attribute.
Unmatched requests retain the method alone as their span name. Spans are exported in
background batches and flushed on graceful shutdown. Export failures are logged
without failing requests. Query strings, headers, bodies, user information and
exception messages are not recorded. Incoming trace headers are not used; each
request starts a new trace and is always sampled.

Start the app, open `/` or sign in, then search in Tempo for service
`oidc-client-demo`. Allow a few seconds for the export batch to arrive.
