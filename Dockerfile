FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive \
    OLLAMA_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1
WORKDIR /app

# System dependencies + security/browser tooling (100% free)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    ca-certificates curl wget git \
    nmap whois dnsutils netcat-openbsd poppler-utils zstd \
    tesseract-ocr xdg-utils sudo \
    firefox \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama (local AI runtime)
RUN curl -fsSL https://ollama.com/install.sh | sh

# Install geckodriver (Mozilla) for Selenium rendering/screenshots
RUN (curl -sL https://github.com/mozilla/geckodriver/releases/download/v0.34.0/geckodriver-v0.34.0-linux64.tar.gz \
    | tar -xz -C /usr/local/bin) && chmod +x /usr/local/bin/geckodriver || true

# Python deps
COPY requirements.txt /app/requirements.txt
RUN python3 -m pip install --break-system-packages --no-cache-dir -r /app/requirements.txt

# App code
COPY . /app
RUN chmod +x /app/entrypoint.sh /app/start.sh /app/stop.sh /app/install.sh

# Volumes for persistent data (models, scans, memory, rag)
VOLUME ["/root/.ollama", "/app/scans", "/app/memory", "/app/ai_output", "/app/rag_store"]

EXPOSE 5050 11434
ENTRYPOINT ["/app/entrypoint.sh"]
