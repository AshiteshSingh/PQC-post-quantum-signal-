FROM python:3.11-slim

WORKDIR /app

# Install Tor and compilation dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

# Ensure shell script line endings are clean LF and executable
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Install Python requirements and package
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir .

EXPOSE 8000

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
