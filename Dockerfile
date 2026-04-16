# MCP Security Scanner - Docker Image
# Multi-stage build for minimal production image

# Stage 1: Builder
FROM python:3.12-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY config/ ./config/
COPY tests/ ./tests/
COPY *.py ./
COPY *.md ./

# Run tests during build
RUN python -m pytest tests/ -v --tb=short

# Stage 2: Production
FROM python:3.12-slim as production

LABEL org.opencontainers.image.title="MCP Security Scanner"
LABEL org.opencontainers.image.description="Security scanner for Model Context Protocol (MCP) servers"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.source="https://github.com/cybathreat/mcp-security-scanner"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user for security
RUN groupadd -r mcpscanner && useradd -r -g mcpscanner mcpscanner

WORKDIR /app

# Install runtime dependencies only
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy necessary files from builder
COPY --from=builder /root/.local/lib/python3.12/site-packages /root/.local/lib/python3.12/site-packages
COPY --from=builder /root/.local/bin /root/.local/bin
COPY --from=builder /build/src ./src
COPY --from=builder /build/config ./config
COPY --from=builder /build/mcp_scanner.py ./
COPY --from=builder /build/config.py ./
COPY --from=builder /build/report.py ./
COPY --from=builder /build/mcp_auth_security.py ./
COPY --from=builder /build/README.md ./
COPY --from=builder /build/DISCLAIMER.md ./

# Create reports directory
RUN mkdir -p /app/reports && chown -R mcpscanner:mcpscanner /app

# Add local bin to PATH
ENV PATH=/root/.local/bin:$PATH

# Switch to non-root user
USER mcpscanner

# Default command
ENTRYPOINT ["python", "src/cli.py"]
CMD ["--help"]

# Health check (basic)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "print('OK')" || exit 1
