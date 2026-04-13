# oidc-client-demo

This repo contains a web app intended to illustrate how to authenticate with OpenID Connect.
It is somewhat inspired by https://github.com/noa-portswigger/flask-lab

## Features

- TOML-based configuration loading
- Uses gunicorn
- OIDC login, callback, protected profile page, and logout

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
cp config.toml.example config.toml
uv run oidc-client-demo
```

The app listens on port `8080`.
