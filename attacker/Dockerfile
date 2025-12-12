FROM debian:stable

# Install system packages & Python with pip
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    tcpdump \
    iproute2 \
    net-tools \
    iputils-ping \
    libpcap-dev \
    libnet1-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries (allow in system env inside container)
RUN pip3 install --no-cache-dir --break-system-packages scapy dnspython requests

WORKDIR /app
COPY . /app

CMD ["tail", "-f", "/dev/null"]
