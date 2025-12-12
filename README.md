# DNS Cache-Poisoning & Defense via DNSSEC

_Last updated: December 12, 2025_

A hands-on security lab that demonstrates a DNS cache-poisoning attack end to end — and then shows how **DNSSEC** validation stops it. The whole environment runs in Docker, with a web control panel to launch the attack, watch DNS resolution flip from a real site to a fake phishing site, and enable DNSSEC to block it.

> Course project for Network Security (ISA 656 / CS 692), George Mason University.

## What it shows

- A caching DNS resolver is poisoned so that `www.example.com` resolves to an attacker-controlled IP.
- Victims are silently redirected from a legitimate "bank" site to a look-alike phishing site.
- Turning on DNSSEC makes the resolver reject the forged records, and the attack fails.

## Features

- **Real vs. fake website** — a legitimate banking site and a phishing clone, so the impact is visible in a browser.
- **One-click attack / reset** from a web UI.
- **DNSSEC panel** — generate keys, sign the zone, and verify signatures live.
- **Latency measurements** comparing resolution with and without DNSSEC.

## Tech stack

| Layer | Tools |
| --- | --- |
| DNS | BIND 9 (authoritative + resolver), DNSSEC |
| Attack tooling | Python, Scapy |
| Backend API | Python, Flask |
| Frontend | React, Vite, Tailwind CSS |
| Orchestration | Docker Compose |

## Architecture

| Component | Address | Role |
| --- | --- | --- |
| Authoritative DNS | 10.0.1.10 | Serves the `example.com` zone (DNSSEC-capable) |
| Caching resolver | 10.0.0.53 | Resolves queries; validates DNSSEC when enabled |
| Real website | 10.0.1.20 | Legitimate banking site (port 8080) |
| Fake website | 10.0.100.100 | Phishing clone (port 8081) |
| Attacker | 10.0.2.100 | Runs the poisoning attack |
| Backend API | localhost:5001 | Orchestrates attack + DNSSEC |
| Frontend UI | localhost:3000 | Control panel |

## Getting started

### Prerequisites
- Docker and Docker Compose
- Node.js (for the frontend)
- Python 3 (for the backend)

### 1. Start the infrastructure
```bash
docker-compose up -d
docker-compose ps      # verify all containers are running
```

### 2. Start the backend API
```bash
cd attacker
python3 poison.py      # serves on http://localhost:5001
```

### 3. Start the frontend
```bash
cd frontend
npm install
npm run dev            # opens http://localhost:3000
```

### 4. Try it
1. **Query DNS** → `www.example.com` resolves to `10.0.1.20` (real site, port 8080).
2. **Start Attack** → query again; it now resolves to `10.0.100.100` (fake site, port 8081).
3. **Reset** to restore normal resolution.
4. **Enable DNSSEC** → run the attack again and watch it fail validation.

> **Note:** DNSSEC signing keys are generated at setup time and are intentionally **not** committed. The `authoritative/keys/` directory is created when you run the DNSSEC setup step.

## Security note

This lab is for education in an isolated Docker network only. Do not point it at, or run any part of it against, real DNS infrastructure.

## Author

Gautham Kumar Karamthot
