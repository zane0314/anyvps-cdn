# AnyVPS

A small, dependency-free control panel for VPS inventory, preferred-IP
sources, subscription links, Sub-Store exports, and Agent-based synchronization.

This public repository is a sanitized distribution generated from a private
production source repository. It contains no production credentials or
deployment-specific data.

## Architecture

- Python standard-library backend.
- SQLite data store.
- Native ES-module frontend with no build step.
- Docker Compose deployment bound to `127.0.0.1:8090`.

## Configure

```bash
cp .env.example .env
```

Set a strong password and session secret, then replace
`https://anyvps.example.com` with the public HTTPS URL of your deployment.

## Run

```bash
docker compose up -d --build
```

## Test

```bash
python3 -m unittest discover -v
```

## Install an Agent

After deploying the panel, run the permanent installer URL from a new VPS:

```bash
curl -fsSL https://anyvps.example.com/install.sh | bash
```

The deployment URL is controlled by `ANYVPS_PUBLIC_URL`.
