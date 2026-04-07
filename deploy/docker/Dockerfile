FROM kalilinux/kali-rolling:latest

LABEL maintainer="Coff0xc" description="Hellcat AI Pentest Framework" version="1.0.0"

ARG HELLCAT_PROFILE=default

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HELLCAT_HOST=0.0.0.0 \
    HELLCAT_PORT=8888 \
    HELLCAT_DATA_DIR=/data/hellcat \
    HELLCAT_AUDIT_DIR=/data/hellcat/audit \
    HELLCAT_PROFILE=${HELLCAT_PROFILE}

# System tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv git curl wget \
    nmap rustscan masscan nikto sqlmap ffuf feroxbuster \
    nuclei httpx-toolkit katana subfinder amass arjun \
    hydra john hashcat netexec smbmap \
    xsstrike sstimap gef adaptixc2 metasploit-mcp wpprobe \
    ghidra gdb binwalk checksec \
    prowler trivy exiftool \
    redis-server \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hellcat

COPY pyproject.toml .
COPY hellcat/ hellcat/

RUN pip3 install --no-cache-dir --break-system-packages ".[full]"

RUN mkdir -p /data/hellcat/audit

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8888/health || exit 1

CMD ["hellcat", "server"]
