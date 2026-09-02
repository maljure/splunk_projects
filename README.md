# Splunk SIEM Log Analysis Lab

A hands-on security analysis lab using Splunk Enterprise to investigate network log data across multiple protocols. Each part focuses on a different log source, walking through data ingestion, field extraction, anomaly detection, and investigative findings.

> **Note:** This is a learning lab built on publicly available sample datasets. No live or production environments were involved.

## Objective

Practice the core workflow of a SOC analyst: get raw logs into a SIEM, make them queryable, hunt for anomalies, separate real signal from noise, and document findings in a way another analyst could act on.

## Environment

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise (Free Trial) |
| Host OS | Ubuntu Linux |
| Access | Splunk Web on `localhost:8000` |
| Dataset | MACCDC 2012 (Mid-Atlantic Collegiate Cyber Defense Competition) via secrepo.com |

The MACCDC dataset is a capture from a live red team vs. blue team competition, which means it contains genuine attack traffic rather than synthetic noise — useful for practicing detection against realistic adversary behavior.

## Parts

| # | Log Source | Focus | Status |
|---|---|---|---|
| 01 | [DNS](./01-dns-analysis/) | Tunneling, exfiltration, reverse-DNS recon | ✅ Complete |
| 02 | HTTP | Web attacks, suspicious user agents, C2 over HTTP | 🔜 Planned |
| 03 | FTP | Credential use, file transfers, anonymous access | 🔜 Planned |
| 04 | SSH | Brute force, lateral movement | 🔜 Planned |
| 05 | Connection logs | Beaconing, long-lived sessions, data volume | 🔜 Planned |
| 06 | Files / SMB | Malware delivery, share access | 🔜 Planned |
| 07 | Correlation | Tying findings across all sources into one incident timeline | 🔜 Planned |

*(Adjust this table as you decide which log sources to cover.)*

## Repository Structure

```
splunk-siem-log-analysis/
├── README.md                      # This file
├── setup/
│   └── splunk-setup.md            # Install, ingest, and field extraction notes
├── 01-dns-analysis/
│   ├── README.md                  # Full DNS investigation writeup
│   ├── queries.md                 # All SPL searches used
│   └── screenshots/
└── 02-http-analysis/              # (and so on)
```

## Skills Demonstrated

- Splunk installation and administration on Linux
- Data ingestion and custom sourcetype configuration
- Search-time field extraction via `props.conf` / `transforms.conf`
- SPL (Search Processing Language): `stats`, `top`, `rex`, `eval`, `timechart`, `where`
- Anomaly detection and threat hunting methodology
- Distinguishing true positives from benign anomalies
- Mapping observed activity to MITRE ATT&CK

## Key Takeaway So Far

The hardest part of log analysis is not finding anomalies — it is deciding which anomalies matter. Part 01 surfaced several high-entropy domain patterns; only one turned out to be malicious. Documenting *why* the others were dismissed is as important as flagging the one that wasn't.
