# AnyVPS

Personal VPS preferred-IP and subscription management panel.

## Architecture

- **Backend**: Python stdlib only (no web framework), modular:
  `app.py` (entry) + `config / db / security / sources / substore / sync / state / server`
- **Frontend**: `static/` — zero-dependency ES-module SPA (Linear light UI), no build step
- **Embedded scripts**: `scripts/detect_common.py` is the single source of truth
  for the `detect_*` helpers; `embedded.py` assembles `/install.sh`
  (collector + agent) from `scripts/*.tpl` in memory at startup

## Local run

```bash
cp .env.example .env
python app.py
```

## Docker

```bash
docker compose up -d --build
```

The app listens on `127.0.0.1:8090` when deployed with Docker Compose.

## Tests

```bash
python3 test_substore_refresh.py
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md)（中文更新日志）.
