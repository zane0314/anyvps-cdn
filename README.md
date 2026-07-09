# anyvps-cdn

Personal VPS preferred-IP and subscription management panel.

## Quick deploy

```bash
apt update
apt install -y git docker.io docker-compose-plugin
systemctl enable --now docker

git clone https://github.com/zane0314/anyvps-cdn.git /root/data/docker_data/anyvps
cd /root/data/docker_data/anyvps

cp .env.example .env
nano .env

docker compose up -d --build
curl -sS http://127.0.0.1:8090/healthz
```

Set these values in `.env` before starting:

```env
ANYVPS_USERNAME=your-login-name
ANYVPS_PASSWORD=change-this-password-before-deploy
ANYVPS_SESSION_SECRET=change-this-random-session-secret
ANYVPS_PUBLIC_URL=https://your-anyvps.example.com
```

Put nginx, Caddy, Cloudflare Tunnel, or another reverse proxy in front of
`127.0.0.1:8090`.

## Collector install command

After the panel is reachable at `ANYVPS_PUBLIC_URL`, install the collector on a
managed VPS with:

```bash
curl -fsSL https://your-anyvps.example.com/install.sh | bash
```

Or override the manager URL explicitly:

```bash
MANAGER_URL=https://your-anyvps.example.com curl -fsSL https://your-anyvps.example.com/install.sh | bash
```

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
