# Splunk SIEM Log Analysis Lab

A hands-on security analysis lab using Splunk to investigate network log data across multiple protocols. Each part focuses on a different log source, walking through data ingestion, field extraction, anomaly detection, and investigative findings.

> **Note:** This is a learning lab built on publicly available sample datasets. No live or production environments were involved.

## Objective

Practice the core workflow of a SOC analyst: get raw logs into a SIEM, make them queryable, hunt for anomalies, separate real signal from noise, and document findings in a way another analyst could act on. Also, get used to using a SIEM to access logs and determine whether they are malicious.

## Environment

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise (Free Trial) |
| Host OS | Ubuntu Linux |
| Access | Splunk Web on `localhost:8000` |
| Dataset | MACCDC 2012 (Mid-Atlantic Collegiate Cyber Defense Competition) via secrepo.com |

The MACCDC dataset is a capture from a live red team vs. blue team competition, which means it contains genuine attack traffic rather than synthetic noise — useful for practicing detection against realistic adversary behavior. I chose this dataset because I thought it would give me a variety of different attacks I could analyze.

## Parts

| # | Log Source | Focus | Status |
|---|---|---|---|
| 01 | [DNS](./DNS_Analysis/) | Tunneling, exfiltration, reverse-DNS recon | ✅ Complete |
| 02 | HTTP | Web attacks, suspicious user agents, C2 over HTTP | 🔜 Planned |
| 03 | FTP | Credential use, file transfers, anonymous access | 🔜 Planned |
| 04 | SSH | Brute force, lateral movement | 🔜 Planned |
| 05 | SMNP | Email communication, timestamps, email subjects | 🔜 Planned |
| 06 | Tunnel | GRE, IPv4, IPv6 | 🔜 Planned |
| 07 | DHCP | IP addresses, lease durations, client requests, server responses | 🔜 Planned |

## Repository Structure

```
splunk_projects/
├── README.md                      # This file
├── setup/
│   └── splunk-setup.md            # Install, ingest, and field extraction notes
├── DNS_Analysis/
│   ├── README.md                  # Full DNS investigation writeup
│   ├── queries.md                 # All SPL searches used
│   └── screenshots/
└── HTTP_Analysis/              # (and so on)
```

## Skills Demonstrated

- Splunk installation and administration on Linux
- Data ingestion and custom sourcetype configuration
- Search-time field extraction via `props.conf` / `transforms.conf`
- SPL (Search Processing Language): `stats`, `top`, `rex`, `eval`, `timechart`, `where`
- Anomaly detection and threat hunting methodology
- Distinguishing true positives from benign anomalies

## Key Takeaway So Far


