#!/bin/bash

echo "=========================================="
echo "🔍 Checking Container Status"
echo "=========================================="
echo ""

echo "1. Container Status:"
docker ps -a --filter "name=authoritative_dns" --filter "name=resolver_dns" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""

echo "2. Authoritative DNS Logs (last 30 lines):"
echo "----------------------------------------"
docker logs authoritative_dns --tail 30 2>&1 || echo "Container not running or accessible"
echo ""

echo "3. Resolver DNS Logs (last 30 lines):"
echo "----------------------------------------"
docker logs resolver_dns --tail 30 2>&1 || echo "Container not running or accessible"
echo ""

echo "4. Testing DNS Resolution:"
echo "----------------------------------------"
docker exec attacker dig @10.0.1.10 example.com SOA +short 2>&1 || echo "Cannot query authoritative"
echo ""

echo "5. Checking Config Files:"
echo "----------------------------------------"
docker exec authoritative_dns cat /etc/bind/named.conf 2>&1 || echo "Cannot read config"
echo ""

echo "=========================================="
