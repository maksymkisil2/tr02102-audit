# Web service image. Build:  docker build -t tr02102-audit .
#                    Run:    docker run -p 8080:8080 -e APP_PASSWORD=... -e SECRET_KEY=... tr02102-audit
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8080 \
    TRUST_PROXY=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-deps -r requirements.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-deps . && rm -rf /app/src

# Run as an unprivileged user (threat T-11).
RUN useradd --system --uid 10001 --no-create-home app
USER app

EXPOSE 8080
# One worker: jobs and rate limits are kept in process memory.
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --timeout 60 --access-logfile - 'tr02102_audit.web:create_app()'"]
