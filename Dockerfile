FROM python:3.11-slim

# Install system dependencies if any are needed for cryptography/sslyze (like gcc)
RUN apt-get update && apt-get install -y gcc g++ libstdc++6 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Upgrade pip and install requirements
COPY rakshak/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -U pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# Copy the actual application
COPY rakshak /app/rakshak

# Set the working directory to where the app is
WORKDIR /app/rakshak

# Railway passes port dynamically, bind to it.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
