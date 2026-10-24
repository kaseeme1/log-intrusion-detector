FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY detector/ ./detector/
COPY sample_logs/ ./sample_logs/

RUN useradd --create-home --uid 10001 analyst
USER analyst

ENTRYPOINT ["python", "-m", "detector"]
CMD ["sample_logs/auth.log"]
