# NIDS-Tool
Python Network Intrusion Detection System (NIDS)

 

A simple yet powerful Network Intrusion Detection System (NIDS) built in Python. This tool captures network packets, detects suspicious activities (like port scanning and brute force attacks), checks malicious IPs against a threat database, and can automatically block attackers using firewall rules.

📌 Features

Real-time Packet Capturing using Scapy

Port Scan Detection (Detects SYN scans)

Threat Intelligence Lookup (AbuseIPDB, Shodan API)

Automated Firewall Blocking (iptables)

Logging & Alerting (Suspicious activity logs)

Lightweight & Extendable

📖 Installation

# Clone the repository
```
git clone https://github.com/yourusername/nids-tool.git
cd nids-tool
```
# Create a virtual environment
```
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```
# Install dependencies
```
pip install -r requirements.txt
```
🚀 Usage

# Run the NIDS tool
python main.py

📜 Documentation & References

Scapy Docs: https://scapy.readthedocs.io/en/latest/

PyShark Docs: https://github.com/KimiNewt/pyshark

AbuseIPDB API Docs: https://docs.abuseipdb.com/

Shodan API Docs: https://developer.shodan.io/api

iptables Guide: https://linux.die.net/man/8/iptables
