# Use minimal Python 3.11 slim image
FROM python:3.11-slim

# Force color output and terminal capabilities
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color \
    FORCE_COLOR=1

WORKDIR /app

COPY requirements.txt setup.py ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

COPY scanner/ ./scanner/
COPY wordlists/ ./wordlists/
COPY main.py ./

RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["argus-eye"]
CMD ["--help"]
