# SharkJack Proof-of-Entry Payload

**Author:** Hackazillarex  
**Description:** Proof-of-entry scan payload for SharkJack devices. Scans the local network for the first 3 live hosts and records their OS, top 10 ports, and services, along with the device’s public IP. Designed for penetration testing and security auditing **only** on networks where you have explicit permission.

---

## Features

- Fetches the **public IP** of the SharkJack device.
- Scans the **first 3 live hosts** on the local subnet.
- Detects **OS information**, **top 10 ports**, and **services**.
- Generates two files:
  - `proof_of_entry_log.txt` — timestamped log of the scan process.
  - `proof_of_entry.txt` — report-ready table with IP, OS, ports, and services.
- LED feedback:
  - Blinking LED while scanning.
  - Solid green LED when the scan completes.

---
