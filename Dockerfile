FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN addgroup --system attackpathgraph \
    && adduser --system --ingroup attackpathgraph attackpathgraph \
    && mkdir -p /app/reports /app/cache /app/templates /app/static \
    && chown -R attackpathgraph:attackpathgraph /app

USER attackpathgraph

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=2)"

ENTRYPOINT ["python", "pentest_graph.py"]
CMD ["--web", "--host", "0.0.0.0", "--port", "5000", "--no-browser"]
