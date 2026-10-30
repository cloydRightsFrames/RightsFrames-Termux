# Build context is the repository root (see core/docker-compose.yml):
#   docker compose -f core/docker-compose.yml up --build
# The API imports both `core.*` and top-level modules from core/, and the
# evidence-export endpoint loads tools/rf_export_evidence.py, so the image
# keeps the repository layout under /app.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PYTHONPATH=/app:/app/core \
    RF_DATA_DIR=/data

WORKDIR /app

COPY core/requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && \
    rm -f /tmp/requirements.txt

COPY core/ /app/core/
COPY tools/rf_export_evidence.py /app/tools/rf_export_evidence.py

RUN useradd \
    --create-home \
    --uid 10001 \
    --shell /usr/sbin/nologin \
    rightsframes && \
    mkdir -p /data && \
    chown -R 10001:10001 /app /data && \
    python -m compileall -q /app

USER 10001

VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=20s \
    --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "core.app:app", "--host", "0.0.0.0", "--port", "8000"]
