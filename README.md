# oidc-client-demo

This repo contains a web app intended to illustrate how to authenticate with OpenID Connect.
It is somewhat inspired by https://github.com/noa-portswigger/flask-lab

## Features

- TOML-based configuration loading
- Uses Hypercorn
- OIDC login, callback, protected profile page, and logout
- Manual refresh-token and Microsoft Graph experiments on the profile page

## Configuration

Copy `config.toml.example` to `config.toml` and update the values for your identity provider.
The identity provider you use needs to support PKCE which enables integration without a
client secret.

You need to register this app with the OpenID connect identity provider you are using. The 
redirect URI migth be needed during registration. An URI using the current basename of this
service, with the path /auth/callback appended

## Local Development

```bash
uv sync
umask 077
uv run python -c 'import secrets; print(secrets.token_urlsafe(32))' > session-key
cp config.toml.example config.toml
uv run oidc-client-demo
```

The app listens on port `8080`.

## Microsoft Entra refresh-token experiment

1. Register a **Web** application in Entra with redirect URI
   `http://localhost:8080/auth/callback`. Use the corresponding public URL if
   running elsewhere. Do not register this server-rendered app's callback as an SPA URI.
2. Create a client secret for the registration. Save its value in a local
   `client-secret` file (mode `0600`) beside `config.toml`, and set
   `oidc.client_secret_path = "client-secret"`. Keep the secret out of Git.
3. Set `oidc.issuer` to
   `https://login.microsoftonline.com/<tenant-id>/v2.0` and `oidc.client_id`
   to the registration's application ID. Set `oidc.scopes` to
   `["openid", "profile", "email", "offline_access", "https://graph.microsoft.com/User.Read"]`.
   Grant consent for the delegated Microsoft Graph `User.Read` permission.
4. Sign in and open `/profile`. It shows whether an access token and refresh
   token were issued, the access-token expiry, and the granted scopes. Press
   **Refresh now** to make a server-to-server refresh request. Press
   **Call Microsoft Graph /me** to test the current access token. A successful
   refresh without a browser redirect to Entra, followed by HTTP 200 from Graph,
   verifies the refresh flow. Try again after the original access token expires.

The app never displays token values. It keeps them in process memory, keyed by
an opaque ID in the signed session cookie, and deletes them on logout. Restarting
the app loses the token records, so sign in again afterward. Run a single worker
for this experiment; a production deployment would need a shared, protected
server-side token store. A refresh failure displays the protocol error code and
leaves the option to sign in again. Signing out of the site does not revoke a
refresh token at Entra.

Set `app.secret_key_path` to a UTF-8 file containing the session signing key.
Relative paths are resolved from the configuration file's directory. Leading and
trailing whitespace is stripped; missing or empty files prevent startup. Inline
`app.secret_key` values are no longer supported. Keep the key stable across restarts
to preserve sessions; replacing it invalidates existing sessions.

The deployment manifest requests `random-secret = "session-key"`, which mounts the
generated key at `/random-secrets/session-key`. The deployment configuration uses
that path.
