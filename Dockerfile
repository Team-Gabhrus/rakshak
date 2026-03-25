FROM python:3.11-slim

# Install system dependencies (gcc for cryptography, Docker CLI for OQS probe)
RUN apt-get update && apt-get install -y \
    gcc g++ libstdc++6 \
    ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Upgrade pip and install requirements
COPY rakshak/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -U pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# Copy the actual application
COPY rakshak /app/rakshak

# Set the working directory to where the app is
WORKDIR /app/rakshak

# Note: To enable the OQS Docker probe for PQC detection, mount the Docker
# socket when running: docker run -v /var/run/docker.sock:/var/run/docker.sock ...
# and ensure the openquantumsafe/curl:latest image is pulled on the host.

# Railway passes port dynamically, bind to it.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
