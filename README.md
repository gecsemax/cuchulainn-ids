> ⚔️ **CuChulainn IDS v5.1** — Apache 2.0 License — Written by **Max Gecse**


**CuChulainn IDS v5.1** is the final open-source release. **Versions 5.2+** are available under commercial license. 

Contact [![LinkedIn](https://img.shields.io/badge/LinkedIn-Max_Gecse-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/max-gecse/) for enterprise licensing and support.


# 🛡️ **CuChulainn IDS v5.1** ![CuChulainn Authorship](https://img.shields.io/badge/Code-Max%20Gecse%20%E2%80%94%20Human%20Authored-darkgreen?style=for-the-badge)      

![CuChulainn](https://img.shields.io/badge/CuChulainn-IDS-003b24?style=for-the-badge&logo=codeforces&logoColor=00ff99)



<p align="center">
  <img src="cuchulainn_benchmark.png" alt="CuChulainn IDS Benchmark">
</p>



<div align="center">

![Human-Written Code](https://img.shields.io/badge/Code-Human--Written-blueviolet?style=for-the-badge)

<!-- Core Project Badges -->
![Version](https://img.shields.io/badge/Version-5.1-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Passing-success?style=for-the-badge)

<!-- Authorship -->
![Author](https://img.shields.io/badge/Author-Max%20Gecse-darkred?style=for-the-badge)
![Human-Written Code](https://img.shields.io/badge/Code-Human--Written-blueviolet?style=for-the-badge)

<!-- Architecture -->
![Architecture](https://img.shields.io/badge/Architecture-Zero--Allocation%20C-orange?style=for-the-badge)
![AVX-512](https://img.shields.io/badge/CPU-AVX--512-critical?style=for-the-badge)
![Event Loop](https://img.shields.io/badge/Capture-AF__PACKET%20%2B%20epoll-yellow?style=for-the-badge)

<!-- Protocol Coverage -->
![Protocols](https://img.shields.io/badge/Protocols-14%2B-lightblue?style=for-the-badge)
![TLS](https://img.shields.io/badge/TLS-ClientHello%20Parser-blue?style=for-the-badge)
![DNS](https://img.shields.io/badge/DNS-Entropy%20%2B%20Tunneling-purple?style=for-the-badge)
![HTTP](https://img.shields.io/badge/HTTP-1.1%20%2F%202.0-orange?style=for-the-badge)

<!-- Performance -->
![Latency](https://img.shields.io/badge/Latency-0.22ms-red?style=for-the-badge)
![CPU](https://img.shields.io/badge/CPU%20Usage-2.1%25%20@%2010Gbps-brightgreen?style=for-the-badge)
![Packet Loss](https://img.shields.io/badge/Packet%20Loss-0%25-success?style=for-the-badge)

<!-- Detection -->
![Detection Rate](https://img.shields.io/badge/Detection-97%25-brightgreen?style=for-the-badge)
![Zero-Day](https://img.shields.io/badge/Zero--Day%20Detection-96%25-yellowgreen?style=for-the-badge)
![False Positives](https://img.shields.io/badge/False%20Positives-%3C0.5%25-blue?style=for-the-badge)

<!-- Footprint -->
![Memory](https://img.shields.io/badge/Memory-58MB-lightgrey?style=for-the-badge)



Version | License | Build | Author | Human‑Written Code  
Architecture | AVX‑512 | Capture  
Protocols | TLS | DNS | HTTP  
Latency | CPU | Packet Loss  
Detection | Zero‑Day | False Positives  
Memory

![Human-Written Code](https://img.shields.io/badge/Code-Human--Written-blueviolet?style=for-the-badge)

# CuChulainn IDS v5.1  
Apache 2.0 License  
Author: Max Gecse

CuChulainn IDS is a network intrusion detection system written in C.  
The project focuses on predictable performance, low latency, and a transparent internal architecture.  
Version 5.1 is the final open‑source release. Later versions are available under a commercial license.

---

## Overview

CuChulainn IDS provides protocol‑aware packet inspection with a compact and auditable codebase.  
The system avoids dynamic memory allocation in the hot path and uses a straightforward processing pipeline:

- AF_PACKET capture with a memory‑mapped ring buffer  
- epoll‑based event loop  
- deterministic protocol parsers  
- optional AVX‑512 accelerated pattern matching  
- scoring and alerting modules  

The goal is to keep the implementation simple, maintainable, and suitable for environments where predictable behaviour is more important than feature complexity.

---

## Protocol Support

CuChulainn IDS includes parsers for:

- TLS (ClientHello inspection)
- DNS
- HTTP/1.1
- HTTP/2
- SMTP
- IMAP
- POP3
- SIP
- FTP
- NTP
- MQTT
- SSH
- QUIC (heuristic)
- CoAP (heuristic)

Each parser extracts a minimal set of fields required for detection logic.

---

## Detection

The detection layer combines:

- lightweight heuristics  
- per‑protocol anomaly checks  
- optional ML‑based scoring (offline‑trained model)  

Examples of implemented checks:

- TLS: SNI anomalies, malformed ClientHello patterns  
- DNS: entropy‑based tunneling indicators  
- HTTP/1.1: suspicious URI patterns  
- HTTP/2: frame‑level irregularities  
- Mail protocols: basic phishing/scraping indicators  

The system is intentionally conservative to reduce false positives.

---

## Performance Characteristics

Performance depends on hardware and traffic profile.  
Typical behaviour on modern x86‑64 systems:

- low CPU usage under sustained load  
- stable throughput at high packet rates  
- sub‑millisecond processing latency  
- zero‑allocation hot path  

The project includes a benchmark report describing the test environment and methodology.

---

## Building

```bash
git clone https://github.com/gecsemax/cuchulainn-ids
cd cuchulainn-ids
make
```

Requirements:

- Linux  
- GCC or Clang  
- optional: AVX‑512 capable CPU  

---

## Running

```bash
sudo ./cuchulainn -i eth0
```

Options:

```
-i <iface>     Network interface
-r <file>      Read packets from pcap
-o <file>      Write alerts to file
```

During execution, the program prints protocol detections, extracted fields, and scoring results.

---

## Repository Structure

```
src/
  main.c
  protocol_parser.c
  tls.c
  dns.c
  http1.c
  http2.c
  smtp.c
  imap.c
  pop3.c
  ...
include/
  protocol_parser.h
docs/
  benchmark-report.md
  architecture.md
LICENSE
README.md
```

---

## Project Status

CuChulainn IDS v5.1 is stable and maintained.  
Future development (v5.2+) continues under a commercial license.

For enterprise licensing or support, contact the author.

---

## License

Apache License 2.0  
Copyright (c) 2026  
Max Gecse
```

