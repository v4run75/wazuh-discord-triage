# syntax=docker/dockerfile:1
# Multi-arch image — works on Raspberry Pi (arm64) and x86_64.
# Build: docker build -t wazuh-discord-triage .
# Run:   docker run --env-file .env wazuh-discord-triage

FROM python:3.12-slim

# Install build dependencies for aiohttp on arm64
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy bot source
COPY bot/ ./bot/

# Run as non-root
RUN useradd -m botuser && mkdir -p /data && chown botuser /data
USER botuser

WORKDIR /app/bot
CMD ["python", "main.py"]
