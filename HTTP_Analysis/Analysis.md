# HTTP Log Analysis
 
**Objective:** Ingest Zeek HTTP logs into Splunk, build field extractions from scratch, and identify reconnaissance, content discovery, injection attempts, and credential attacks against web services.
 
**Dataset:** `http.log` from the MACCDC 2012 capture
**Index:** `http_log` | **Sourcetype:** `bro_http`
**Sample analyzed:** 600,000 of 2,048,442 events (29.3%), covering approximately **07:30 – 12:50 on 2012-03-16**
 
---
 
## Why HTTP?
 
HTTP is the loudest protocol on most networks and the one attackers reach for first, because it is the one thing guaranteed to be allowed outbound and inbound. Three properties make it worth hunting in:
 
- **Everything is an endpoint.** Every path on a web server is a potential target, and the server tells you whether each one exists. That turns a web application into something that can be mapped by brute force.
- **Input reaches the database.** Login forms, search boxes, and URL parameters are all user-controlled strings that end up in backend queries. SQL injection has been the top web risk for two decades for this reason.
- **Attacker-controlled identity.** User-Agent, method, credentials — all of it is whatever the client says it is. This cuts both ways, and in this dataset it cut in the analyst's favour.
All three appeared here. Notably, **every tool in this capture identified itself honestly**, either by name or by behaviour it made no attempt to disguise.
 
---
 
## Methodology
 
### 1. Ingestion
 
Three separate problems had to be solved before a single analytical query could run.
 
**Problem 1 — File size vs. license quota.**
 
The source file was 1.3 GB across 2,048,442 lines. Splunk Free enforces a 500 MB/day indexing quota, and the browser upload path is not designed for multi-gigabyte files regardless of license.
 
Rather than sampling randomly, a **contiguous** slice was taken so that time-based queries would remain meaningful:
 
```bash
head -600000 http.log > http_sample.log
```
 
A random sample would have broken every `timechart` and every duration calculation in this report. Contiguity was the requirement, not volume.
 
**Problem 2 — No header block.**
 
Zeek TSV logs normally begin with a `#fields` / `#types` declaration. This file had been stripped of it and began directly at data:
 
```
1331901000.000000	CHEt7z3AzG4gyCNgci	192.168.202.79	50465	192.168.229.251	80	1	HEAD ...
```
 
With no header, Splunk indexed 27 unnamed tab-separated values per event. Field names had to be supplied manually, mapped against the Zeek 2.x `http.log` schema. Column count was verified before writing the extraction:
 
```bash
awk -F'\t' '{print NF}' http.log | sort | uniq -c | sort -rn | head
```
 
**Problem 3 — Timestamps resolving to 2026.**
 
Every event indexed at upload time despite a `props.conf` stanza with correct `TIME_PREFIX` and `TIME_FORMAT`, verified as loaded via `btool`. The cause was an inherited default:
 
```
MAX_DAYS_AGO = 2000
```
 
Splunk parsed the epoch timestamp correctly, judged March 2012 to be implausibly old, discarded it, and fell back to index time. The gap between capture and analysis is roughly **5,290 days**. This is the same failure documented in the FTP lab, and it will affect every remaining log in this dataset — it is a property of the dataset's age, not of any one protocol.
 
**Final configuration.**
 
`transforms.conf`:
 
```
[bro_http_fields]
DELIMS = "\t"
FIELDS = "ts","uid","src_ip","src_port","dest_ip","dest_port","trans_depth","method","host","uri","referrer","user_agent","request_body_len","response_body_len","status_code","status_msg","info_code","info_msg","filename","tags","username","password","proxied","orig_fuids","orig_mime_types","resp_fuids","resp_mime_types"
```
 
`props.conf`:
 
```
[bro_http]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = ^
TIME_FORMAT = %s.%6N
MAX_TIMESTAMP_LOOKAHEAD = 25
KV_MODE = none
MAX_DAYS_AGO = 10951
REPORT-bro_http = bro_http_fields
```
 
Zeek's native `id.orig_h` / `id.resp_h` names were deliberately remapped to `src_ip` / `dest_ip`. Dotted field names require backtick-quoting in every SPL expression, which becomes an error source across a long analysis.
 
📷 `screenshots/field-extraction.png`
 
### 2. Method distribution
 
```
index=http_log sourcetype=bro_http | stats count by method | sort - count
```
 
| Method | Count | Assessment |
|---|---|---|
| `HEAD` | 273,105 | Headers only, no body — scanning, see Finding 4 |
| `GET` | 202,470 | Includes the DirBuster campaign, Finding 1 |
| `POST` | 121,257 | 96% of these are a single campaign, Finding 3 |
| `OPTIONS` | 1,985 | Method enumeration — reconnaissance |
| `-` | 391 | Zeek could not parse a request line at all |
| `DELETE` / `PUT` | 202 / 121 | Write and destroy attempts |
| `CONNECT` / `RPC_CONNECT` | 115 / 39 | Proxy tunneling attempts |
| `SEARCH` / `PROPFIND` | 97 / 47 | WebDAV — `SEARCH` is the MS03-007 vector |
| `TRACE` / `TRACK` | 24 / 17 | Cross-Site Tracing probes |
| `GNUTELLA` | 40 | P2P traffic on port 80 — not HTTP at all |
| `NESSUS` | 19 | Scanner announcing itself as a verb |
| `CFFWFE`, `RWXDSY`, `BXNTPG` | 2, 2, 1 | Random strings — method fuzzing |
| `Secure`, `some` | 20, 20 | Mixed case — binary data misread as a request line |
 
**The method field is not a list of methods.** Zeek takes the first token of the request line and records it without validation, so anything appearing in that position lands here. That makes it an unintentional inventory of everything that touched port 80 and failed to speak HTTP properly.
 
Three distinct signals fall out of it:
 
- **Scanners naming themselves.** `NESSUS` is sent deliberately to observe how the server handles an unknown verb.
- **Method fuzzing.** `CFFWFE`, `RWXDSY`, `BXNTPG` are random uppercase strings testing whether the server rejects malformed verbs cleanly. Nikto does exactly this.
- **Non-HTTP traffic.** `GNUTELLA`, `Secure`, `some`, and the 391 unparseable events. The 8,605 `400 Bad Request` responses in the next section corroborate this from the server's side.
📷 `screenshots/method-distribution.png`
 
### 3. Status codes — and the number that reframed the dataset
 
```
index=http_log sourcetype=bro_http | top limit=20 status_code
```
 
| Code | Count | Percentage |
|---|---|---|
| `404` Not Found | 406,843 | 68.36% |
| `200` OK | 160,850 | 27.03% |
| `400` Bad Request | 8,605 | 1.45% |
| `303` See Other | 5,261 | 0.88% |
 
**Two thirds of all requests asked for something that does not exist.** No population of users produces that ratio. Note also what is *absent*: there is no meaningful `403 Forbidden` volume. Nothing was being denied — things were simply not there. That distinction matters, and separating "you may not have this" from "this does not exist" is the difference between an access-control problem and an enumeration problem.
 
### 4. Locating the 404s — distribution vs. average
 
The top-15 URI list accounts for roughly 25% of traffic and is dominated by two paths (`/main.php` at 116,665 and `/` at 23,832). The obvious question is where the other 406,843 failures live.
 
```
index=http_log sourcetype=bro_http
| stats dc(uri) as unique_uris, count as total_requests
| eval avg_requests_per_uri=round(total_requests/unique_uris, 2)
```
 
Result: **317,684 unique URIs, 1.89 requests per URI on average.**
 
That average is misleading and worth calling out. Two URIs hold 140,000 requests between them; the remaining 317,682 share the rest. The average flattens exactly the structure under investigation. Testing the tail directly:
 
```
index=http_log sourcetype=bro_http status_code=404
| stats count by uri | where count <= 2
| stats count as uris_hit_once_or_twice, sum(count) as total_404s_from_these
```
 
| Metric | Value |
|---|---|
| URIs requested once or twice | 306,169 |
| 404s generated by them | 336,785 |
| Share of all 404s | **82.8%** |
 
Requesting 306,169 distinct paths that do not exist, each essentially once, is not browsing, broken links, or a misconfigured application. It is dictionary enumeration, and it is the dominant activity in this capture.
 
📷 `screenshots/404-long-tail.png`
 
### 5. Timeline
 
```
index=http_log sourcetype=bro_http | timechart span=5m count by method limit=5 useother=f
```
 
| Window | Dominant activity | Peak |
|---|---|---|
| 07:30 – 07:55 | `HEAD` | 2,973 / 5 min |
| 08:05 – 08:35 | `GET` | **40,121 / 5 min** (≈134 req/sec) |
| 09:00, 10:05 | `OPTIONS` spikes | 440 and 412 |
| 09:30 – 09:45 | `GET` second wave | 15,195 / 5 min |
| 10:15 – 10:45 | Near-silence | — |
| 10:50 – 11:50 | `POST` flood | 29,009 / 10 min |
 
Human traffic ramps and decays. This timeline is a series of rectangles — hard onset, plateau, hard stop — separated by intervals of nothing. Each block is a tool starting and finishing. The 07:30 → 07:35 transition (142 requests to zero) and the 08:15 → 08:20 transition (301 to 40,121) are the clearest examples.
 
📷 `screenshots/timeline-by-method.png`
 
---
 
## Findings
 
### 🔴 Finding 1 — Directory brute-force campaign (DirBuster)
 
**Source:** `192.168.203.63` → **Target:** `192.168.229.101`
 
| Metric | Value |
|---|---|
| Requests | 268,221 |
| 404 responses | 268,109 |
| Unique URIs | 255,362 |
| Failure rate | **100.0%** |
| Duration | 120.6 minutes |
| Request rate | **2,223 req/min** (≈37/sec) |
 
**The tool identified itself.** The User-Agent field on this traffic reads:
 
```
DirBuster-0.12 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
```
 
DirBuster is an OWASP content-discovery tool: point it at a server, supply a wordlist, and it requests every entry looking for unlinked admin panels, backup files, and config directories. A 255,362-entry wordlist producing a 100% failure rate is the tool working exactly as designed against a server that had none of those paths.
 
This single host accounts for **44.7% of all sampled traffic** and **65.9% of all 404s**.
 
**A second User-Agent on the same host:**
 
```
Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.11) Gecko/20101013 Ubuntu/9.04 (jaunty) Firefox/3.6.11
```
 
Same source, same target, same window. DirBuster's User-Agent is configurable, so this is either the operator toggling the setting mid-run or browsing manually alongside the scan. Either way, **the "Firefox" traffic from this host is not a person browsing.** User-Agent is attacker-controlled and cannot be treated as identity — it is useful here only because this operator did not bother to hide.
 
**Outcome: total failure.** Zero successful discoveries. The wordlist did not match the target's content.
 
**Recommended action:** Low urgency on the target — nothing was found. Higher urgency on the source: `192.168.203.63` is running offensive tooling and should be isolated and examined. Consider rate-limiting and 404-threshold alerting on the web tier; a host generating 37 failed requests per second for two hours is trivially detectable and was not stopped.
 
📷 `screenshots/dirbuster-ua.png`
 
### 🔴 Finding 2 — SQL injection campaign across eight servers
 
**Source:** `192.168.202.110`
**Targets:** `192.168.27.203`, `.229.251`, `.22.253`, `.27.253`, `.229.156`, `.22.102`, `.22.252`, `.27.102`
 
Injection payloads were recovered from the **HTTP basic-auth password field**, meaning the attacker was injecting directly into the authentication mechanism:
 
```
index=http_log sourcetype=bro_http username!="-" username!=""
| stats count by src_ip, dest_ip, username | sort - count
```
 
| Payload | Count (vs `.27.203`) | Purpose |
|---|---|---|
| `'` | 9 | Error-based probe — does a single quote break the query? |
| `' or '1=1` | 30 | Authentication bypass — always-true condition |
| `6666` | 30 | Numeric control value, paired with every injection |
| `\xe0' AND 0=1 LIMIT 0 UNION SELECT 1, 1 LIMIT 1; --` | 6 | UNION-based extraction with multibyte escape evasion |
| `admin`, `root` | 59, 24 | Standard credential guessing |
 
**Reading the payloads:**
 
- `' or '1=1` closes the quoted string in a query such as `WHERE username='$input'` and appends a condition that is always true, matching every row regardless of credentials.
- The UNION payload is considerably more advanced: `AND 0=1` suppresses legitimate rows, `UNION SELECT` appends attacker-controlled rows, `--` comments out the remainder. The leading `\xe0` is a **multibyte encoding evasion** — a character-set trick used to break escaping routines that do not handle encodings correctly. This is automated tooling, not hand-typed input.
- The bare `'` is the reconnaissance step. Send one quote, watch for a SQL error, confirm the injection point, then send the real payload.
- `6666` appearing at counts **identical** to `' or '1=1` on every target is a tool fingerprint: the same wordlist cycling a numeric value and an injection string against each host in turn.
This also explains this host's earlier statistics — 128,456 requests across only 27,676 unique URIs, a repetition ratio of 4.6:1. Unlike DirBuster, which requests each path once, this tool hit the same endpoints repeatedly with varying payloads.
 
**Outcome: unconfirmed.** Zeek's `http.log` records the credentials submitted but not the application's response body, so whether any injection succeeded cannot be determined from this log alone. The activity is unambiguous; the result is not.
 
**Recommended action:** Isolate `.202.110`. Review application logs and database logs on all eight targets for the corresponding time window — that is where success or failure will be visible. Parameterised queries are the fix; input filtering for `'` and `1=1` is not.
 
📷 `screenshots/sqli-payloads.png`
 
### 🟠 Finding 3 — High-volume automated POST campaign against `/main.php`
 
**Source:** `192.168.202.102`
**Targets:** up to 5 servers simultaneously — `.21.202`, `.23.202`, `.24.202`, `.26.202`, `.28.202`
**Window:** 10:50 – 11:50, 2012-03-16
 
```
index=http_log sourcetype=bro_http uri="/main.php" method=POST
| bin _time span=10m
| stats count, dc(src_ip) as sources, dc(dest_ip) as targets, avg(request_body_len) as avg_req by _time
```
 
| Time | Requests | Sources | Targets |
|---|---|---|---|
| 08:50 – 09:40 | 1 – 4 | 1 – 2 | 1 – 3 |
| **10:50** | 15,913 | 1 | 1 |
| **11:00** | 15,810 | 2 | 4 |
| **11:10** | 18,512 | 1 | 4 |
| **11:20** | 23,405 | 3 | 5 |
| **11:30** | 29,009 | 2 | 5 |
| **11:40** | 13,825 | 1 | 2 |
| 12:00 – 12:50 | 6 – 30 | 1 | 1 |
 
**99.95% of all `/main.php` POST traffic occurred inside this single hour.** There is effectively no baseline — near-silence, one hour at up to 48 requests/second, then near-silence again.
 
**Payload characteristics:**
 
```
index=http_log sourcetype=bro_http src_ip="192.168.202.102" uri="/main.php" method=POST
| stats count, avg(request_body_len), stdev(request_body_len),
        avg(response_body_len), stdev(response_body_len)
```
 
| Metric | Value | Interpretation |
|---|---|---|
| Request body mean | 147.6 bytes | Form submission |
| Request body stdev | 32.5 (22%) | Bounded variation — same form, different field values |
| Response body mean | 7,684 bytes | — |
| Response body stdev | 622 (8%) | **Near-identical response every time** |
 
The response consistency is the key measurement. It rules out a webshell: a backdoor executing commands returns wildly varying output sizes — a directory listing, a file dump, a one-line error. An 8% variance across 116,514 requests means the server returned the same page nearly every time. The request-side variation, bounded but real, is what a form produces when field contents change length between submissions.
 
**The response-size anomaly:**
 
```
index=http_log sourcetype=bro_http uri="/main.php" | rare limit=20 response_body_len
```
 
| Size | Count | Share |
|---|---|---|
| 7,783 / 7,792 / 7,800 | 113,280 | 97.2% |
| **3,790** | **2,776** | **2.4%** |
| 6,550 / 5,170 | 200 / 199 | 0.34% |
 
The 3,790-byte response — roughly half the normal page — was traced to its source:
 
| Target | Count | First | Last |
|---|---|---|---|
| `192.168.23.202` | 1,586 | 11:11:56 | 11:44:27 |
| `192.168.26.202` | 450 | 11:34:39 | 11:45:34 |
| `192.168.24.202` | 444 | 10:57:55 | 11:08:52 |
| `192.168.28.202` | 295 | 11:29:11 | 11:37:51 |
 
**2,775 of 2,776 came from `192.168.202.102`**, all status 200, all inside the flood window, replicated across four independent servers. Four separate hosts returning the same abnormal page to the same client at the same time indicates an application state change specific to this traffic — a rejection page, an error page, or a lockout response.
 
**Assessment — stated with its limits.** The evidence supports: *high-volume automated POST activity against a login endpoint on five servers, with bounded-length request bodies and an anomalous server response appearing only during the campaign.* This is consistent with **credential brute-forcing**. It cannot be confirmed, because Zeek's `http.log` does not capture POST bodies. Confirming it requires web server or application logs.
 
**Recommended action:** Isolate `.202.102`. Review authentication logs on all five targets for 10:50 – 11:50. Determine what the 3,790-byte response is — that single question likely resolves whether this succeeded. Implement account lockout and rate limiting; 48 login attempts per second should not be possible.
 
📷 `screenshots/post-flood-timeline.png`
📷 `screenshots/response-size-anomaly.png`
 
### 🟠 Finding 4 — Basic-auth credential brute-force
 
**Primary source:** `192.168.202.76` → `192.168.229.156`, username `admin`, **1,669 attempts**
 
Two further hosts converged on the same target with the same username:
 
| Source | Target | Username | Attempts |
|---|---|---|---|
| `192.168.202.76` | `192.168.229.156` | `admin` | 1,669 |
| `192.168.202.110` | `192.168.229.156` | `admin` | 179 |
| `192.168.202.103` | `192.168.229.156` | `admin` | 39 |
| `192.168.202.110` | `192.168.27.203` | `admin` | 59 |
| `192.168.202.110` | `192.168.27.203` | `root` | 24 |
| `192.168.204.70` | `192.168.202.78` | `zeus` | 16 |
| `192.168.203.62` | `192.168.202.78` | `cmurder` | 8 |
 
**Three separate hosts brute-forcing the same account on the same server** suggests either coordinated effort or independent operators converging on an obvious target.
 
`zeus` and `cmurder` are worth separating from the rest. These are not default or dictionary usernames. An attacker trying non-standard account names either has prior knowledge of the environment or harvested them from somewhere — which makes `192.168.202.78` worth examining for what was exposed and where those names came from.
 
Unlike Finding 3, these credentials appear in Zeek's output because HTTP basic auth transmits them in a header the parser reads. Form-based logins do not appear at all — which is precisely why Finding 3 remains unconfirmed while this one is directly observable.
 
📷 `screenshots/auth-attempts.png`
 
### 🟡 Finding 5 — Targeted reconnaissance (Nmap NSE)
 
**Source:** `192.168.202.79` → `192.168.229.251`
 
```
1331901000.000000  192.168.202.79  →  192.168.229.251  HEAD  /DEASLog02.nsf  404
1331901000.010000  192.168.202.79  →  192.168.229.251  HEAD  /DEASLog03.nsf  404
1331901000.030000  192.168.202.79  →  192.168.229.251  HEAD  /DEASLog04.nsf  404
```
 
User-Agent: `Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)`
 
Requests arrive 10–20 milliseconds apart from sequential source ports, using `HEAD` to retrieve headers without response bodies — the efficient choice when the only question is whether a path exists.
 
The `.nsf` extension identifies **Lotus Domino** database files. `DEASLog02.nsf`, `decsadm.nsf`, `dirassist.nsf`, `doladmin.nsf` are default Domino administrative databases, frequently left world-readable and containing configuration and directory data. This is a targeted NSE script checking a known list, not a generic scan.
 
Volume: 6,771 requests, 1,339 unique URIs, 64.7% failure, 20.5 req/min. Small and precise — the opposite profile to Finding 1.
 
**Assessment:** Reconnaissance, unsuccessful against this target. Its value is as an indicator of intent and as the opening phase of the timeline.
 
### 🟢 Finding 6 — Anomalies investigated and ruled out
 
**The eight `302` responses on `/main.php`**
 
An initial hypothesis held that the small number of redirects among 116,627 identical `200` responses might represent successful authentications — a redirect to a dashboard is what a successful login typically produces.
 
Checking the actual events refuted it:
 
| Time | Source | Target |
|---|---|---|
| 09:00:05 | `192.168.202.76` | `192.168.21.202` |
| 09:08:53 | `192.168.202.76` | `192.168.21.202` |
| 09:44:56 | `192.168.202.94` | `192.168.23.202` |
| 09:47:26 | `192.168.203.45` | `192.168.26.202` |
| 11:01:46 | `192.168.202.76` | `192.168.26.202` |
| 11:04:48 | `192.168.202.76` | `192.168.26.202` |
| 11:28:35 | `192.168.202.103` | `192.168.22.202` |
| 11:32:32 | `192.168.202.103` | `192.168.25.202` |
 
**None originate from `192.168.202.102`.** Four different sources, five different destinations, spread across three hours. Unrelated traffic sharing a URI.
 
The finding is instead that `/main.php` **exists on servers across at least five subnets** — the CCDC pattern, where every competing team runs identical infrastructure. `/main.php` is not one target; it is a standard application replicated environment-wide.
 
**Cache-busting parameters**
 
Referrers on these events read `/main.php?stuff=1971893073`, `?stuff=583174662`, `?stuff=976741887` — random integers on a parameter the application ignores. This is cache-busting: appending junk so no proxy or browser serves a stored copy. It confirms automated tooling but is not itself an attack. The same signature appears in the top-URI list as `/main.php?stuff=` and `/top.php?stuff=` at 592 hits each.
 
**Probable scoring infrastructure**
 
| Source | Requests | Unique URIs | req/min |
|---|---|---|---|
| `192.168.202.87` | 399 | 38 | 1.4 |
| `192.168.202.90` | 719 | 83 | 2.6 |
| `192.168.202.103` | 780 | 126 | 2.9 |
 
Low, steady rates over 4.5+ hours against a small fixed set of paths. `.202.87` requests `/reporting/generateReport.php` and `/flagsubmission/getHandleInfo.php` — "flag submission" is competition infrastructure, not attack tooling. Classified as benign with the caveat that `.202.103` also appears in Finding 4; a host can run both.
 
**Probable human user**
 
`192.168.202.108` — 751 requests, **15 unique URIs**, 13 minutes, 12.4% failure. Short session, narrow path variety, mostly successful. This is what an actual person looks like in this dataset, and it is the only host that looks like one.
 
**Why this section exists:** Every entry here would fire a naive detection rule. A redirect among failed logins, a randomised URL parameter, an automated client polling a web app — all are structurally anomalous and all are explainable. Determining which is the work.
 
---
 
## Summary
 
| Finding | Host | Outcome | Severity |
|---|---|---|---|
| DirBuster content discovery, 255K paths | `192.168.203.63` | **Failed** — 100% 404 | **High** |
| SQL injection across 8 servers | `192.168.202.110` | Unconfirmed | **High** |
| POST flood vs `/main.php`, 5 servers | `192.168.202.102` | Unconfirmed | **High** |
| Basic-auth brute-force, `admin` | `192.168.202.76` (+2) | Unconfirmed | Medium |
| Nmap NSE Lotus Domino recon | `192.168.202.79` | Failed | Medium |
| Method fuzzing, WebDAV/XST probing | Multiple | Failed | Low |
| Scoring infrastructure | `.202.87`, `.202.90` | Benign | Benign |
 
**Attack progression observed:**
 
```
07:30  Reconnaissance      Nmap NSE, Lotus Domino path probing
08:05  Content discovery   DirBuster, 255,362 paths, 100% failure
09:00  Method enumeration  OPTIONS spikes across multiple hosts
09:30  Second scan wave    15,195 GET / 5 min
10:50  Credential attack   116,514 POSTs, 5 servers, 1 hour
       (throughout)        SQL injection vs 8 servers, basic-auth brute-force
```
 
This is textbook progression: map the target, enumerate its content, probe its inputs, attack its authentication. It is visible in this log **only because the timestamps were fixed** — with every event stacked at index time, none of this sequence exists.
 
The dominant characteristic of this capture is failure. Two thirds of all requests returned 404. The single largest campaign achieved a 100% failure rate. What succeeded — or may have — was quieter: injection payloads against eight servers and a one-hour credential run that generated less than half the traffic of the scan nobody could have missed.
 
---
 
## Lessons Learned
 
**Averages hide the thing you are looking for.** "1.89 requests per URI" describes a healthy website. The actual distribution was 306,169 paths requested once and two paths requested 140,000 times. The mean was arithmetically correct and analytically useless. Every aggregate in this report was checked against its distribution before being trusted.
 
**Check attribution, not just counts.** The eight `302` responses fit the successful-login hypothesis perfectly at the aggregate level — small count, anomalous status, right endpoint. They came from four hosts that were not the attacker. A pattern matching a hypothesis is not the same as the specific events supporting it, and the difference is one query.
 
**Success rate says nothing about intent.** `/main.php` was initially assessed as the legitimate application in use, on the basis that it accounted for 72% of all successful responses. It was one host POSTing to one endpoint 116,514 times. High success rates are what a working attack looks like from the server's side.
 
**Rarity is signal.** `NESSUS` appeared 19 times, `CFFWFE` twice, `BXNTPG` once — a rounding error in a 600,000-event dataset. They identify a vulnerability scanner and a fuzzing tool precisely because nothing legitimate produces them. Alerting on `GET` is meaningless; alerting on a method that is not a method is nearly free.
 
**Tools name themselves more often than they should.** DirBuster announced itself in the User-Agent. Nmap announced itself. Nessus sent its own name as an HTTP verb. None of this is reliable — User-Agent is attacker-controlled and trivially changed — but it is worth checking first, because attackers frequently do not bother. The one host that *did* rotate its User-Agent (Finding 1, switching to a Firefox string) gave itself away anyway through source IP and timing.
 
**Request and response sizes are underrated.** `request_body_len` and `response_body_len` distinguished a credential attack from a webshell without access to a single payload byte. An 8% response variance across 116,514 requests said "same page every time"; high variance would have said "command execution." Neither conclusion required the content.
 
**Know what your log cannot tell you.** Zeek's `http.log` records basic-auth credentials but not POST bodies. That single limitation is why Finding 4 names exact usernames while Finding 3 can only describe a shape. Stating the boundary is more useful than guessing past it — and it identifies exactly which additional log source would resolve the question.
 
**Sample deliberately.** 600,000 of 2,048,442 lines were analyzed, taken contiguously from the start of the capture. Random sampling would have been defensible for the URI distribution and destructive for every timing-based conclusion in this report — and the timing is where most of the findings came from.
 
---
 
## Appendix — Key Queries
 
```
# Baseline and time span
index=http_log sourcetype=bro_http
| stats count, dc(src_ip) as unique_sources, dc(dest_ip) as unique_dests,
        min(_time) as first_event, max(_time) as last_event
| convert ctime(first_event) ctime(last_event)
 
# Method distribution
index=http_log sourcetype=bro_http | stats count by method | sort - count
 
# Status code distribution
index=http_log sourcetype=bro_http | top limit=20 status_code
 
# Top requested URIs
index=http_log sourcetype=bro_http | top limit=15 uri
 
# Long-tail test — is this enumeration?
index=http_log sourcetype=bro_http
| stats dc(uri) as unique_uris, count as total_requests
| eval avg_requests_per_uri=round(total_requests/unique_uris, 2)
 
# Where the 404s actually live
index=http_log sourcetype=bro_http status_code=404
| stats count by uri | where count <= 2
| stats count as uris_hit_once_or_twice, sum(count) as total_404s_from_these
 
# Per-source failure profile — identifies scanners
index=http_log sourcetype=bro_http
| stats count as total, count(eval(status_code=404)) as errors_404,
        dc(uri) as unique_uris by src_ip
| eval fail_pct=round(errors_404*100/total, 1)
| sort - total | head 15
 
# Traffic shape over time
index=http_log sourcetype=bro_http
| timechart span=5m count by method limit=5 useother=f
 
# Most-targeted hosts
index=http_log sourcetype=bro_http status_code=404
| stats count by dest_ip | sort - count | head 10
 
# Tool identification via User-Agent
index=http_log sourcetype=bro_http src_ip="192.168.203.63"
| stats count, dc(uri) as unique_uris, values(method) as methods,
        values(user_agent) as agents by dest_ip | sort - count
 
# POST activity by source and endpoint
index=http_log sourcetype=bro_http method=POST
| stats count by src_ip, uri | sort - count | head 15
 
# Payload characteristics — brute-force vs webshell
index=http_log sourcetype=bro_http src_ip="192.168.202.102" uri="/main.php" method=POST
| stats count, avg(request_body_len) as avg_req, stdev(request_body_len) as stdev_req,
        avg(response_body_len) as avg_resp, stdev(response_body_len) as stdev_resp,
        min(request_body_len), max(request_body_len)
 
# Response size outliers
index=http_log sourcetype=bro_http uri="/main.php" | rare limit=20 response_body_len
 
# Trace an anomalous response to its source
index=http_log sourcetype=bro_http uri="/main.php" response_body_len=3790
| stats count, min(_time) as first, max(_time) as last by src_ip, dest_ip, status_code
| convert ctime(first) ctime(last) | sort - count
 
# Campaign phase analysis
index=http_log sourcetype=bro_http uri="/main.php" method=POST
| bin _time span=10m
| stats count, dc(src_ip) as sources, dc(dest_ip) as targets,
        avg(request_body_len) as avg_req by _time | sort _time
 
# Basic-auth credentials and injection payloads
index=http_log sourcetype=bro_http username!="-" username!=""
| stats count by src_ip, dest_ip, username | sort - count
 
# Per-host behavioural profile — separates humans from tools
index=http_log sourcetype=bro_http
| stats range(_time) as duration, count as requests, dc(uri) as unique_uris by src_ip
| eval duration_min=round(duration/60, 1), req_per_min=round(requests/(duration/60), 1)
| sort - requests | head 15
```
 
