# ODOSIAN AI Engine - Container Image
# Using Alpine base image for zero critical/high vulnerabilities & minimal image size (~50MB)
FROM python:3.12-alpine

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system build dependencies and ensure all security packages are updated
RUN apk add --no-cache --upgrade \
    build-base \
    git

# Copy packaging specifications first to leverage Docker layer caching
COPY pyproject.toml requirements.txt README.md LICENSE ./

# Install project dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e ".[dev]"

# Copy application directories and project assets
COPY configs/ ./configs/
COPY prompts/ ./prompts/
COPY resources/ ./resources/
COPY scripts/ ./scripts/
COPY src/ ./src/
COPY tests/ ./tests/
COPY .env.example ./

# Default environment variables
ENV ODOSIAN_ENVIRONMENT=production \
    ODOSIAN_LOG_LEVEL=INFO \
    ODOSIAN_LOG_FORMAT=json \
    ODOSIAN_LOG_OUTPUT=stdout

EXPOSE 8000

CMD ["uvicorn", "src.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
