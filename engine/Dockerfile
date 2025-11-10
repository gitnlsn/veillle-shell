# Python engine Dockerfile

FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 nlsn

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /var/log/nlsn-monitor && \
    chown -R nlsn:nlsn /var/log/nlsn-monitor /app

USER nlsn

# Expose API port
EXPOSE 8888

# Run the API server
CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8888"]
