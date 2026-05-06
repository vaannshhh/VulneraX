# ─────────────────────────────────────────────────────────────────────────────
# VulneraX — Multi-stage Docker build
# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder — installs Python deps
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Install to a prefix so we can copy cleanly to the runtime image
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="VulneraX Contributors"
LABEL description="Intelligent Automated Vulnerability Assessment Framework"
LABEL org.opencontainers.image.source="https://github.com/yourorg/vulnerax"

# Install runtime system deps (nmap, nikto available via apt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application source
COPY . .

# Create output directory
RUN mkdir -p scan_results

# Expose API port
EXPOSE 8000

# Default command: start the API server
# Override with: docker run vulnerax python main.py scan <target> --full
CMD ["python", "main.py", "api", "--host", "0.0.0.0", "--port", "8000"]

# ─────────────────────────────────────────────────────────────────────────────
# Usage examples:
#
#   Build:
#     docker build -t vulnerax .
#
#   Run API:
#     docker run -p 8000:8000 vulnerax
#
#   Run CLI scan:
#     docker run --rm vulnerax python main.py scan https://example.com --full
#
#   Mount output directory:
#     docker run -p 8000:8000 -v $(pwd)/scan_results:/app/scan_results vulnerax
# ─────────────────────────────────────────────────────────────────────────────
