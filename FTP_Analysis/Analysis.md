# FTP Log Analysis

**Objective:** Ingest FTP logs into Splunk, extract usable fields, and hunt for evidence of exploitation, unauthorized access, or data exfiltration over FTP.

**Dataset:** `ftp.log` from the MACCDC 2012 capture
**Index:** `ftp_logs` | **Sourcetype:** `ftp_zeek` | **Events:** 5,796

---

## Why FTP?

FTP is a 1971 protocol still running on production networks in 2012 — and in many environments today. It is attractive to attackers for three reasons:

- **No encryption.** Credentials, commands, and file contents all cross the wire in cleartext. Anyone with visibility into the traffic reads the passwords for free.
- **Pre-authentication attack surface.** The server must parse client input before deciding whether the client is allowed to be there. Historically this has produced a long list of buffer overflow vulnerabilities.
- **Permissive defaults.** Anonymous access is trivial to enable and easy to forget about.

All three showed up in this dataset — and notably, the vulnerability that actually caused damage was the boring one.

---

## Methodology

### 1. Ingestion

The log was uploaded to Splunk with a custom index and sourcetype.

**Problem encountered:** Every event was timestamped at upload time rather than March 2012. Additionally, Splunk indexed each line as an unparsed blob — no field-based searching was possible.

**Root cause (fields):** Zeek logs are tab-delimited with no header Splunk recognizes automatically.

**Root cause (timestamps):** This one was not obvious. A `props.conf` stanza with the correct `TIME_PREFIX` and `TIME_FORMAT` was verified as loaded via `btool` — and still did not work. The culprit was an inherited default:

```
MAX_DAYS_AGO = 2000
```

Splunk treats any extracted timestamp older than this threshold as implausible and silently discards it, falling back to index time. The dataset is from March 2012; the analysis was performed in 2026 — roughly **5,286 days**, well beyond the limit. Splunk was parsing the timestamp correctly and then throwing it away.

**Fix:** Raise `MAX_DAYS_AGO` to its maximum and define a search-time field extraction mapping the Zeek FTP schema to named fields.

`transforms.conf`:

```
[zeek_ftp_fields]
DELIMS = "\t"
FIELDS = "ts","uid","src_ip","src_port","dest_ip","dest_port","user","password","command","arg","mime_type","file_size","reply_code","reply_msg","passive","data_orig_h","data_resp_h","data_resp_p","fuid"
```

`props.conf`:

```
[ftp_zeek]
CHARSET = LATIN-1
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = ^
TIME_FORMAT = %s.%6N
MAX_TIMESTAMP_LOOKAHEAD = 20
MAX_DAYS_AGO = 10951
REPORT-zeek_ftp = zeek_ftp_fields
```

📷 `screenshots/field-extracted.png`

### 2. Baseline — all events

```
index=ftp_logs sourcetype=ftp_zeek
```

Time range set to **All time**. Note that with `MAX_DAYS_AGO` corrected, the timeline is now usable — before the fix, all 5,796 events stacked into a single millisecond and every time-based query was meaningless.

📷 `screenshots/all-events.png`

### 3. Command distribution

```
index=ftp_logs sourcetype=ftp_zeek | stats count by command | sort - count
```

| Command | Purpose | Assessment |
|---|---|---|
| `STOR` | Upload file | 1,353 attempts — all denied, see Finding 1 |
| `RETR` | Download file | 112 — includes the successful exfiltration in Finding 2 |
| `APPE` | Append to file | 72 |
| `DELE` | Delete file | Destructive intent, all denied |
| `PASV` / `PORT` | Data channel setup | Protocol overhead |

📷 `screenshots/command-stats.png`

### 4. Transfer outcomes

Counting commands is not the same as counting what actually happened. FTP reply codes separate attempts from successes:

```
index=ftp_logs sourcetype=ftp_zeek command IN ("RETR","STOR","APPE")
| stats count by command, reply_code | sort command, - count
```

| Reply code | Meaning |
|---|---|
| `226` | Transfer complete — success |
| `550` | Requested action not taken — permission denied or file not found |
| `-` | No reply at all — server never responded |

The result reframed the entire dataset. All 1,353 `STOR` operations returned **550**, and every `APPE` returned **no reply whatsoever**. A raw count suggested mass upload activity; the reply codes showed a near-total failure rate.

The `file_size` field corroborated this independently — it was blank on every `STOR` and `APPE` event, because Zeek populates it from the server's completion response, and no completion ever occurred.

📷 `screenshots/reply-codes.png`

### 5. Client fingerprinting via the password field

Anonymous FTP conventionally sends an email address as the password. Every client tool uses a different default string, which makes the password column an accidental software inventory:

```
index=ftp_logs sourcetype=ftp_zeek | stats count by user, password | sort - count
```

| User | Password | What it identifies |
|---|---|---|
| `ftp` | `password@example.com` | Automated tooling — the Finding 1 host |
| `anonymous` | `password` | Not an email at all — scripted or manually typed |
| `anonymous` | `IEUser@` | Internet Explorer default |
| `anonymous` | `mozila@example.com` | **Misspelled** — see below |
| `anonymous` | `anon@lulz.com` | Human-typed, 2012 hacker culture reference |
| `anonymous` | `nessus@nessus.org` | Nessus vulnerability scanner |
| `anonymous` | `towsonadmin@towson.edu` | CCDC participant institution |
| `anonymous` | `Cuno`, `test` | Credential guessing |

`mozila@example.com` is worth pausing on. Genuine Firefox sends `mozilla@example.com` with two L's. A single missing character means this is a tool impersonating a browser and getting it slightly wrong — an unforced error, and a free detection opportunity for anyone who bothers to check.

📷 `screenshots/password-fingerprints.png`

---

## Findings

### 🔴 Finding 1 — Automated exploitation campaign (unsuccessful)

**Source host:** `192.168.202.102`
**Targets:** 9+ hosts including `.21.101`, `.22.101`, `.23.101`, `.24.101`, `.27.101`, `.28.101`, `.23.103`

**Observed activity:**

`APPE` commands where the argument field contained several kilobytes of binary data rather than a filename:

```
APPE ftp://192.168.23.103/./\x83\xc7<\xbe\xf0]\xbd\xde\x87\xf73...
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90...
```

**Why this is malicious:**

- The `\x90` bytes are x86 **NOP instructions** — a NOP sled. An attacker pads a payload with them so that if the hijacked instruction pointer lands anywhere in that region, execution slides forward into the actual shellcode. It is an accuracy cushion, and it has no legitimate reason to appear in a filename.
- The `\xeb` bytes are short jumps; the `\xff`, `\xc7` clusters are shellcode body. The structure is a textbook buffer overflow targeting the server's argument parsing.
- `user` is `<unknown>` and `password` is `-` on these events. **No authentication occurred.** This is pre-auth exploitation, which is precisely what makes this class of bug valuable.
- Targets were hit **sequentially, seconds apart, with an identical payload**. No human operator works that way. This is an automated exploitation tool with a target list.
- The same host also issued `STOR` and `DELE` across six servers — write and delete attempts. The intent was not only access but modification and destruction.

**Outcome: complete failure.** Every `APPE` received no server reply. Every `STOR` returned 550. `192.168.202.102` does not appear anywhere in the successful-transfer results. Nothing was written, deleted, or executed via FTP.

**Recommended action:** Isolate `.102` — its presence indicates an attacker already has a foothold on that host and is attempting lateral movement. Patch or replace the FTP daemons on all targeted servers regardless of the failure; the campaign failing does not mean the vulnerability is absent.

📷 `screenshots/nop-sled.png`

### 🟠 Finding 2 — Successful data exfiltration via anonymous access

**Source host:** `192.168.202.94`
**Target:** `192.168.25.101`
**Credential:** `anonymous`
**Result:** 86 distinct files retrieved, all with reply code `226`

**What was taken:**

The full application tree of what appears to be a **healthcare patient management system** (`qdept`):

| File | Significance |
|---|---|
| `dept/qdept/qdept.db` | SQLite database — patient records |
| `dept/qdept/schema.sql` | Database structure |
| `dept/qdept/config.py` | Application configuration — likely hardcoded credentials |
| `dept/qdept/dbtools.py` | Database access layer |
| `dept/qdept/user.py`, `user_management.py`, `registration.py` | Authentication logic |
| `dept/qdept/patient_management.py` | Patient data handling |
| `dept/nginx.conf`, `guniconf.py` | Server configuration |
| `dept/qdept/.lab_client.py.swp` | Vim swap file — leftover editing artifact |

**Why this is significant:**

- This was not a single opportunistic grab. The entire directory tree came down — source, config, templates, database, and the bundled Python virtualenv. That is enough to read the application offline, extract every credential in it, audit it for vulnerabilities at leisure, and stand up an identical instance to practice against.
- `patient_management` and a patient database make this a **data breach with regulatory weight**, not merely a security event.
- The `.swp` file is a detail worth noting. Vim swap files contain file contents, survive cleanup routines, and are specifically hunted for by attackers.

**The timeline is the most revealing part:**

```
index=ftp_logs sourcetype=ftp_zeek src_ip="192.168.202.94" | timechart span=1m count
```

| Time | Activity |
|---|---|
| 15:41 – 15:43 | Light activity — connecting, directory listing, orientation |
| 15:44 – 15:47 | **Four minutes of complete silence** |
| 15:48 – 15:49 | Sharp sustained burst — the bulk of the extraction |

Automated tools do not pause. A scanner that finds an open share begins downloading immediately. A four-minute gap followed by a decisive burst reads as a **human being**: connected, looked around, found `dept/qdept/` and a `.db` file, decided it was worth taking, and initiated a recursive retrieval.

Compare against Finding 1 — `.102` fired continuously at nine hosts with no hesitation. Different actors, different tradecraft. One is a tool spraying exploits. This one made a decision.

**Recommended action:** Disable anonymous FTP on `192.168.25.101` immediately. Treat the patient database as breached and initiate the corresponding disclosure process. Rotate every credential appearing in `config.py`. Investigate `.94` for how it knew to target this host.

📷 `screenshots/exfil-filelist.png`
📷 `screenshots/exfil-timeline.png`

### 🟢 Finding 3 — Anomalies investigated and ruled out

**Large executable transfer**

A single `application/x-executable` file accounted for roughly 84% of all bytes transferred:

```
ftp://192.168.25.101/dept/env/bin/python — 2,585,932 bytes — reply 226
```

An unexpected executable crossing the network is exactly the shape of malware staging, and it warranted a look. It resolved as the **Python interpreter bundled inside the application's virtualenv** — a large binary that happened to sit within the directory tree being copied wholesale in Finding 2. Not attacker tooling. Worth explicitly ruling out rather than assuming.

**Nessus scanner traffic**

`nessus@example.com` and `nessus@nessus.org` appeared as anonymous FTP passwords. Nessus is a legitimate commercial vulnerability scanner from Tenable, not malware — and notably, it identifies itself honestly rather than hiding.

The question is therefore not *"is this malicious"* but *"was this authorized."* In a CCDC context this is almost certainly red team enumeration or competition scoring infrastructure. On a production network, unauthorized Nessus traffic would mean someone has a scanning platform inside the perimeter — a serious finding despite the tool being benign.

**Browser and human traffic**

`IEUser@`, `towsonadmin@towson.edu`, and `justinwray@justinwray.com` represent ordinary users browsing an open FTP share. Unremarkable in isolation — though their presence confirms the anonymous share was broadly discoverable, which is context for Finding 2.

**Why this section exists:** Flagging a 2.5 MB executable or a scanner signature is trivial to automate. Determining that one is a virtualenv interpreter and the other is a self-identifying audit tool is the part requiring an analyst. Both would generate false positives in a naive rule.

---

## Summary

| Finding | Host(s) | Outcome | Severity |
|---|---|---|---|
| Buffer overflow campaign via `APPE` + `STOR`/`DELE` attempts | `192.168.202.102` | Failed — no server replies, all 550 | **High** |
| Anonymous exfiltration of healthcare app + patient DB | `192.168.202.94` → `192.168.25.101` | **Succeeded** — 86 files, all 226 | **Critical** |
| Nessus vulnerability scanning | Multiple | Authorization unverified | Medium |
| Browser / user anonymous access | Multiple | Benign | Benign |

A single host on `192.168.202.0/24` conducted an automated buffer overflow campaign against nine FTP servers using shellcode embedded in `APPE` arguments, alongside `STOR` and `DELE` attempts. **The entire campaign failed.**

Separately and quietly, a different host on the same subnet used ordinary anonymous access to retrieve the complete source tree and patient database of a healthcare application in under nine minutes. **This succeeded completely**, and required no exploit, no malware, and no elevated privileges.

The server's configuration denied every write operation and permitted every read. That asymmetry is the vulnerability.

---

## Lessons Learned

**The loud attack is rarely the one that hurts you.** `.102` generated 10,000+ events, tripped every structural anomaly a detection rule could look for, and achieved nothing. `.94` generated a few hundred events using a legitimate protocol feature and walked away with a patient database. If an analyst had been watching alerts live during this window, the buffer overflows would have consumed their attention while the real breach completed.

**Configuration beats detection here.** The `.94` incident lasted nine minutes end to end, with the meaningful portion compressed into two. No alert requiring human triage catches that in time. The effective control was never a detection rule — it was not enabling anonymous read access in the first place.

**Reply codes are not optional.** `1,353 STOR operations` and `1,353 failed STOR operations` are opposite conclusions drawn from the same events. Counting commands without checking outcomes would have produced a report claiming mass data staging that never happened.

**Timing reveals the actor.** A four-minute gap distinguished a human making a decision from a tool executing a list. Volume and command mix said very little; the shape of the timeline said a great deal.

**Field extraction is the real work.** Reproducing the DNS lab's `props.conf` / `transforms.conf` approach was straightforward. The `MAX_DAYS_AGO` failure was not — the configuration was demonstrably correct and loaded, and still silently failed. Verifying with `btool` and then reasoning about *why* correct config produces wrong output was more valuable than the parsing itself.

**Verify your own numbers before publishing them.** A duplicate ingest during troubleshooting inflated event counts and byte sums by exactly 2×. Distinct counts (`dc(arg)` = 86 files) were unaffected, but aggregate figures were not. Catching this before writing the report — rather than after — is most of the job.

---

## Appendix — Key Queries

```
# Baseline
index=ftp_logs sourcetype=ftp_zeek

# Command distribution
index=ftp_logs sourcetype=ftp_zeek | stats count by command | sort - count

# Transfer outcomes by reply code
index=ftp_logs sourcetype=ftp_zeek command IN ("RETR","STOR","APPE")
| stats count by command, reply_code | sort command, - count

# Successful transfers only
index=ftp_logs sourcetype=ftp_zeek command IN ("RETR","STOR") reply_code>=200 reply_code<300
| stats count, sum(file_size) as bytes by src_ip, dest_ip, command | sort - count

# Client fingerprinting
index=ftp_logs sourcetype=ftp_zeek | stats count by user, password | sort - count

# Per-host behavioral profile
index=ftp_logs sourcetype=ftp_zeek
| stats count, dc(command) as unique_cmds, dc(uid) as connections by src_ip, dest_ip
| sort - count

# What .94 actually took
index=ftp_logs sourcetype=ftp_zeek src_ip="192.168.202.94" command="RETR" reply_code=226
| stats count, dc(arg) as files, sum(file_size) as bytes, values(arg) as filenames by dest_ip

# Exfiltration timeline
index=ftp_logs sourcetype=ftp_zeek src_ip="192.168.202.94" | timechart span=1m count

# File type analysis
index=ftp_logs sourcetype=ftp_zeek command="RETR" reply_code>=200 reply_code<300
| stats count, sum(file_size) as bytes by mime_type | sort - bytes
```
