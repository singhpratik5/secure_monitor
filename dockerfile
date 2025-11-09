FROM ubuntu:22.04

LABEL maintainer="your.email@example.com"
LABEL description="Secure Monitoring Daemon"
LABEL version="1.0.0"

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        libssl-dev \
        ca-certificates \
        procps \
        net-tools \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy source code
COPY . .

# Build application
RUN make clean && make && make install

# Create necessary directories
RUN mkdir -p /var/run /var/log /var/lib/secure_monitor \
    && mkdir -p /etc/secure_monitor

# Copy configuration
COPY config/monitor.conf /etc/secure_monitor/

# Expose ports
EXPOSE 8888/tcp 8888/udp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z localhost 8888 || exit 1

# Run as non-root user (optional, requires additional configuration)
# RUN useradd -r -s /bin/false monitor
# USER monitor

# Start daemon
CMD ["/usr/local/bin/secure_monitor", "-standalone", "-p", "8888"]