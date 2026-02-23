# Dockerfile — CodeGuard API
# Optimized for free-tier RAM (keeps image lean)
# Build: docker build -t codeguard-api .
# Run:   docker run -p 8000:8000 codeguard-api

FROM python:3.12-slim AS base

# System deps — git for repo scanning, minimal everything else
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Node + JS tools (optional — comment out to save RAM on free tier)
# RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
#     && apt-get install -y nodejs \
#     && npm install -g eslint typescript njsscan \
#     && rm -rf /var/lib/apt/lists/*

# Copy application
COPY server.py .

# Non-root user for security
RUN useradd -m -u 1001 codeguard
USER codeguard

EXPOSE 8000

# Single worker on free tier — scale up for paid
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--timeout-keep-alive", "30"]
