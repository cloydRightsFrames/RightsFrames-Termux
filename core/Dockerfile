# RightsFrames core API image.
# Build from the REPOSITORY ROOT (the image needs core/, tools/ and verifier/):
#   docker build -f core/Dockerfile -t rightsframes-core .
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app:/app/core \
    RF_DATA_DIR=/data

WORKDIR /app

COPY core/requirements.txt /tmp/requirements.txt

# Hash-locked, wheels only: no sdist build scripts execute during the image build.
RUN python -m pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
    && python -m pip check \
    && rm -f /tmp/requirements.txt

COPY core/__init__.py core/app.py core/rf_core.py core/rf_auth.py core/rf_api_v1.py /app/core/
COPY core/evidence/ /app/core/evidence/
COPY tools/rf_export_evidence.py /app/tools/rf_export_evidence.py
COPY verifier/rf_verify.py /app/verifier/rf_verify.py

RUN useradd \
        --create-home \
        --uid 10001 \
        --shell /usr/sbin/nologin \
        rightsframes \
    && mkdir -p /data \
    && chown 10001:10001 /data \
    && chmod 0700 /data \
    && python -m compileall -q /app \
    && python -c "import core.app"

USER 10001

VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=20s \
    --retries=3 \
    CMD python -c "import json, urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3); raise SystemExit(0 if json.load(r).get('status') == 'ok' else 1)"

CMD ["uvicorn", "core.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
