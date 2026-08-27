# 🛡️ CyberShield Lab
### A Student Cybersecurity Defensive Workflow Project
**Author:** Ajayi Joshua Abayomi | Babcock University | 300L Information Technology

---

## 📌 Project Overview

CyberShield Lab is a beginner-to-intermediate cybersecurity project that simulates
a **real-world defensive security workflow** using Python and C++. It covers five
core areas a cybersecurity analyst deals with daily:

1. **Network Reconnaissance**     — Discover live hosts on a network
2. **Port Scanning**              — Find open ports (C++ for speed)
3. **Malware Scanning**           — Check files against known threat signatures
4. **Vulnerability Tracking**     — Match software versions against known CVEs
5. **Secure Access Testing**      — Test password strength and credential safety

> ⚠️ **Ethical Notice:** This tool is built for educational use ONLY.
> Only scan networks and systems you own or have explicit permission to test.
> Unauthorized scanning is illegal and unethical.

---

## 🗂️ Project Structure

```
cybershield-lab/
├── main.py                    ← Main launcher (start here)
├── modules/
│   ├── recon.py               ← Network host discovery (Python)
│   ├── malware_scan.py        ← File malware signature scanner (Python)
│   ├── vuln_tracker.py        ← CVE vulnerability tracker (Python)
│   └── access_tester.py       ← Password & access strength tester (Python)
├── cpp/
│   ├── port_scanner.cpp       ← Fast TCP port scanner (C++)
│   └── Makefile               ← Build file for C++ scanner
├── data/
│   ├── malware_signatures.json ← Known malware file hashes (SHA-256)
│   ├── cve_database.json       ← Sample CVE vulnerability entries
│   └── common_passwords.txt    ← Top common weak passwords list
├── reports/                   ← Auto-generated scan reports saved here
└── README.md
```

---

## 🚀 Setup & Run

### Step 1 — Build the C++ Port Scanner
```bash
cd cpp/
make
cd ..
```

### Step 2 — Run the Lab
```bash
python3 main.py
```

### Requirements
- Python 3.8+
- g++ (C++ compiler)
- Linux/macOS (or WSL on Windows)

---

## 🧠 What You Learn

| Module              | Concept Covered                                      |
|---------------------|------------------------------------------------------|
| Reconnaissance      | ICMP ping, socket-based host discovery, IP ranging   |
| Port Scanning (C++) | TCP 3-way handshake, socket programming, threading   |
| Malware Scanning    | File hashing (SHA-256), signature databases          |
| Vulnerability Track | CVE format, version comparison, risk scoring         |
| Access Testing      | Password entropy, brute-force awareness, OWASP rules |

