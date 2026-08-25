# Use minimal Python 3.11 slim image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory inside container
WORKDIR /app

# Install dependencies first for Docker layer caching
COPY requirements.txt setup.py ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

# Copy application source code and default wordlists
COPY scanner/ ./scanner/
COPY wordlists/ ./wordlists/
COPY main.py ./

# Create non-root user for security
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Set CLI entrypoint
ENTRYPOINT ["argus-eye"]
CMD ["--help"]
