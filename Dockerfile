# Small, reproducible image for running the detector anywhere.
FROM python:3.12-slim

# Don't write .pyc files; print output immediately (nice for logs).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY detector/ ./detector/
COPY sample_logs/ ./sample_logs/

# Security best practice: don't run as root inside the container.
RUN useradd --create-home --uid 10001 analyst
USER analyst

ENTRYPOINT ["python", "-m", "detector"]
CMD ["sample_logs/auth.log"]
