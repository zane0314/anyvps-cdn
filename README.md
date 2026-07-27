# AnyVPS

Personal VPS preferred-IP and subscription management panel.

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
