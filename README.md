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
| 01 | [DNS](./DNS_Analysis/Analysis.md) | Reconnaissance, Command-and-control, Data exfiltration | ✅ Complete |
| 02 | [HTTP](./HTTP_Analysis/Analysis.md) | Reconnaissance, Content discovery, Injection attempts | ✅ Complete |
| 03 | [FTP](./FTP_Analysis/Analysis.md) | Exploitation, Unauthorized access, Data exfiltration | ✅ Complete |
| 04 | [SSH](./SSH_Analysis/Analysis.md) | Reconnaissance, Lateral movement, Credential attacks | ✅ Complete |
| 05 | [DHCP](./DHCP_Analysis/Analysis.md) | Lease behavior, address churn, client profiling | ✅ Complete |

## Repository Structure

```
splunk_projects/
├── README.md                   # This file
├── DNS_Analysis/               
│   ├── Analysis.md             # Full DNS investigation writeup
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

## Key Takeaways

- **Field extraction is most of the work.** Every log arrived as headerless Zeek TSV that Splunk couldn't parse, and every one hit the same silent `MAX_DAYS_AGO` failure that threw away correct 2012 timestamps. Using `btool` to confirm what Splunk was *actually* loading, not what I thought I'd configured, became the first step of every lab.
- **Hunt for behavior, not signatures.** Blocklists only find what is already known. The strongest detections came from structure: 63-character DNS labels exposed tunneling, a sessions-per-target ratio separated SSH brute force from scanning, and response-size variance ruled out a webshell in HTTP.
- **Averages hide the attack.** HTTP averaged 1.89 requests per URI while 306K paths were hit exactly once; one DHCP client made up half of all traffic and shifted the real peak; ranking SSH targets by attacker count buried the most-attacked host entirely. Check the distribution, and try more than one sort, before trusting a number.
- **Count outcomes, not attempts.** 1,353 FTP uploads looked like mass data staging until reply codes showed every single one was denied. What an attacker *tried* and what *succeeded* are opposite conclusions from the same events.
- **The loud attack is rarely the one that hurts.** An FTP buffer-overflow campaign generated 10,000+ events and achieved nothing, while a quiet anonymous login took a patient database in nine minutes. The most damaging finding needed no exploit, just a legitimate feature and a bad configuration.
- **Know what each log can't tell you.** HTTP logs record basic-auth credentials but not POST bodies, SSH encrypts before authentication so usernames never appear, and this DHCP log has no message types. Naming the gap, and the log source that would close it, is more useful than guessing past it.
- **Timing, silence, and empty fields are evidence.** A four-minute pause marked a human decision in the FTP exfiltration, empty SSH `auth_attempts` showed most connections never reached login, and 13 hours of DHCP silence revealed a scheduled shutdown.
- **False positives show judgment.** McAfee reputation lookups looked like DNS tunneling, a 2.5 MB executable was a Python virtualenv, and a chatty DHCP client wasn't a starvation attack. Every lab includes a ruled-out section, because explaining why something is benign is the part a detection rule can't do.
