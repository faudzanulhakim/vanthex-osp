# VANTHEX — Offensive Security Platform (v1.0.0)
# Native alternative: see INSTALL.md. This image packages the same
# self-built engine; no ready-made scanner tools are installed or invoked.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first (better layer caching). Everything the engine needs
# is pure-python / manylinux wheels — no compiler toolchain required.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persistent state (SQLite DB incl. CVE cache, and the secrets vault key)
# lives on the /data volume; the entrypoint symlinks it into /app.
RUN mkdir -p /data && chmod +x /app/docker-entrypoint.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=4)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["python", "app2.py", "5000"]
