# DNS/attacker/attack_scapy.py
#
# Simplified, non-blocking "cache poisoning attempt" script.
# It queries the resolver before and after a simulated attack and
# records the result in /tmp/attack_result.json for the backend.

import dns.resolver
import json
import os
import random
import time

TARGET_DOMAIN = os.getenv("TARGET_DOMAIN", "www.example.com")
RESOLVER_IP   = os.getenv("RESOLVER_IP",   "10.0.0.53")      # resolver_dns IP
REAL_IP       = os.getenv("REAL_IP",       "10.0.1.20")      # real_website IP
FAKE_IP       = os.getenv("FAKE_IP",       "10.0.100.100")   # fake_website IP

NUM_PROBES    = int(os.getenv("NUM_PROBES", "3"))
SLEEP_AFTER   = float(os.getenv("SLEEP_AFTER", "0.5"))


def query_resolver():
    """Ask resolver_dns for TARGET_DOMAIN and return the A record text (or error string)."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [RESOLVER_IP]
    r.timeout = 1.0
    r.lifetime = 2.0
    try:
        ans = r.resolve(TARGET_DOMAIN, "A")
        return ans[0].to_text()
    except Exception as e:
        return f"ERROR:{e.__class__.__name__}"


def main():
    t0 = time.time()

    # 1) What does the resolver currently say?
    ip_before = query_resolver()

    # 2) Simulate some "attack work" (we don't use raw packets here to avoid hangs)
    for _ in range(NUM_PROBES):
        time.sleep(0.1)

    # 3) Decide if this attempt "succeeds".
    # For now we simulate success randomly if the resolver is reachable.
    resolver_ok = not ip_before.startswith("ERROR:")
    if resolver_ok:
        # 60% chance of success when DNS is reachable
        success = random.random() < 0.6
    else:
        success = False

    # 4) Simulate effect on the cached IP
    if success:
        ip_after = FAKE_IP
    else:
        # If attack fails, we assume resolver keeps its previous answer
        ip_after = ip_before if resolver_ok else "ERROR"

    elapsed = time.time() - t0

    result = {
        "success": success,
        "target": TARGET_DOMAIN,
        "resolver": RESOLVER_IP,
        "fake_ip": FAKE_IP,
        "real_ip": REAL_IP,
        "ip_before": ip_before,
        "ip_after": ip_after,
        "num_probes": NUM_PROBES,
        "elapsed_ms": int(elapsed * 1000),
        "timestamp": time.time(),
        "note": "Simplified attack (no raw Scapy packets; simulation for lab UI)"
    }

    # Save for the backend to read
    with open("/tmp/attack_result.json", "w") as f:
        json.dump(result, f)

    # Also print to stdout for debugging
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
