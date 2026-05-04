FROM python:3.12-slim

LABEL org.opencontainers.image.title="DRMF Graph Collector"
LABEL org.opencontainers.image.description="Modular Graph-first collector for DRMF security control evidence"
LABEL org.opencontainers.image.licenses="Internal"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OUTPUT_PATH=/output/drmf_output.json \
    GRAPH_BASE_URL=https://graph.microsoft.com/v1.0

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system drmf \
    && useradd --system --gid drmf --home-dir /app --shell /usr/sbin/nologin drmf \
    && mkdir -p /output \
    && chown -R drmf:drmf /app /output

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY main.py /app/main.py
COPY drmf_collector /app/drmf_collector

USER drmf

ENTRYPOINT ["python", "/app/main.py"]
