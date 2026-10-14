FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY decoyguard ./decoyguard
RUN pip install --no-cache-dir . && useradd -r -u 10001 decoy && mkdir /data && chown decoy /data

USER decoy
WORKDIR /data
# Config and the SQLite database live in the /data volume.
ENV DG_CONFIG=/data/decoyguard.json DG_DB_PATH=/data/decoyguard.db
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/_dg/health', timeout=2)" || exit 1

ENTRYPOINT ["decoyguard"]
CMD ["serve"]
