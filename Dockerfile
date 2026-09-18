FROM python:3.10-slim

# Prevent python from writing pyc files to disc & buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies needed for scapy and network operations
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements or setup file first to leverage Docker cache
COPY setup.py .
COPY README.md .

# Install dependencies (this creates a cached layer for dependencies)
RUN pip install --no-cache-dir scapy numpy pandas scikit-learn joblib tqdm rich colorama requests aiofiles

# Copy the whole source code
COPY . .

# Install the package itself
RUN pip install --no-cache-dir -e .

# Set the entrypoint to the syn command
ENTRYPOINT ["syn"]
CMD ["-h"]
