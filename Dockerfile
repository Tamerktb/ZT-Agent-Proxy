FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY zt_gateway/ zt_gateway/
COPY test_proxy.py ./

RUN pip install --no-cache-dir .

ENV ZT_PROXY_HOST=0.0.0.0 \
    ZT_PROXY_PORT=8000 \
    ZT_MGMT_PORT=8080 \
    ZT_LOG_LEVEL=INFO \
    ZT_DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 8000 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"

CMD ["zt-gateway"]
