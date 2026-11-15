FROM python:3.10-slim

# Prevent python from writing pyc files to disc & buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SYN_CACHE_DIR=/app/cache
ENV SYN_LOGS_DIR=/app/logs
ENV SYN_REPORTS_DIR=/app/reports

WORKDIR /app

# Install system dependencies needed for scapy and raw packet operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy packaging metadata first to leverage Docker layer cache
COPY setup.py README.md ./

# Install runtime Python dependencies
RUN pip install --no-cache-dir scapy numpy scikit-learn joblib rich

# Copy source code and pre-trained verified models
COPY . .

# Create runtime directories and install package in editable mode
RUN mkdir -p /app/cache /app/logs /app/reports \
    && pip install --no-cache-dir --no-deps -e .

ENTRYPOINT ["syn"]
CMD ["-h"]
