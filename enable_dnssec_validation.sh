#!/bin/bash
echo "🔐 Enabling DNSSEC Validation..."

# Get KSK from authoritative
KSK=$(docker exec attacker dig @10.0.1.10 example.com DNSKEY +short | grep "^257")

if [ -z "$KSK" ]; then
    echo "❌ No KSK found! Run 'Setup DNSSEC' first."
    exit 1
fi

echo "✅ KSK found"

# Configure resolver with trust anchor
docker exec resolver_dns bash -c "cat > /etc/bind/named.conf << EOF
options {
    directory \"/tmp\";
    recursion yes;
    allow-query { any; };
    allow-recursion { any; };
    listen-on { 10.0.0.53; };
    forward only;
    forwarders { 10.0.1.10; };
    dnssec-validation yes;
};

trust-anchors {
    example.com static-key $KSK;
};

zone \"example.com\" {
    type forward;
    forward only;
    forwarders { 10.0.1.10; };
};

zone \"example.local\" {
    type forward;
    forward only;
    forwarders { 10.0.1.10; };
};
EOF"

echo "✅ Configured trust anchor"

# Restart resolver
docker-compose restart resolver_dns
sleep 5

echo "✅ Resolver restarted"
echo ""
echo "Testing validation..."
docker exec attacker dig @10.0.0.53 www.example.com +dnssec | grep -E "(flags:|RRSIG)"
echo ""
echo "Look for 'ad' flag and RRSIG records above ☝️"
