FROM python:3.11-slim

WORKDIR /app

# Install Tor, compiler, and libffi
RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Pre-create Tor directories and permissions
RUN mkdir -p /var/lib/tor/hidden_service \
    && chmod 700 /var/lib/tor/hidden_service \
    && chown -R debian-tor:debian-tor /var/lib/tor

# Copy repository files
COPY . /app

# Install dependencies and package
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
