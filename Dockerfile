FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANYVPS_DATA_DIR=/data \
    ANYVPS_PORT=8090

WORKDIR /app
COPY app.py /app/app.py

RUN useradd -r -u 10001 -g root anyvps && \
    mkdir -p /data && \
    chown -R anyvps:root /data /app

USER anyvps
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=3).read()"

CMD ["python", "/app/app.py"]
