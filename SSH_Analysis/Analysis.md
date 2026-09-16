# SSH Log Analysis

**Objective:** Ingest Zeek SSH logs into Splunk, build field extractions from scratch, and identify reconnaissance, lateral movement, and credential attacks against SSH services — working entirely from connection metadata, because the protocol denies you everything else.

**Dataset:** `ssh.log` from the MACCDC 2012 capture
**Index:** `ssh_log` | **Sourcetype:** `ssh`
**Sample analyzed:** 7,143 of 7,143 events (100%), covering **07:30:11 on 2012-03-16 to 15:56:33 on 2012-03-17** — a 32.4-hour window

---

## Why SSH?

SSH is the administrative protocol. It is how systems are managed, and therefore how a compromised network is managed by whoever compromised it. Three properties make it worth hunting in:

- **It is the lateral movement channel.** An attacker who lands on one internal host uses SSH to reach the next. Perimeter monitoring never sees this; only internal sensor placement does.
- **It is high-value by definition.** A successful SSH authentication is typically shell access, not a web session. The blast radius of one success is larger than for almost any other protocol.
- **It is encrypted before it is authenticated.** This is the defining constraint of the entire analysis. Credentials, commands, and session content are inside the encrypted channel and a network sensor cannot reach them.

That third property inverts the method. The HTTP analysis worked because payloads were readable — injection strings in auth fields, User-Agents naming their own tools, response sizes distinguishing a brute-force from a webshell. **None of that is available here.** What remains is who connected to whom, how often, and when. Every finding in this report was derived from those three facts alone.

---

## Methodology

### 1. Ingestion

**Problem 1 — Timestamps resolving to 2026.**

Every event indexed at upload time despite a correct `TIME_PREFIX` and `TIME_FORMAT`. The cause was the inherited default:

```
MAX_DAYS_AGO = 2000
```

Splunk parsed the epoch timestamp correctly, judged March 2012 to be implausibly old, discarded it, and fell back to index time. The gap between capture and analysis is roughly **5,290 days**, well past the 2,000-day ceiling. Raising it to its maximum of 10,951 days resolved it.

This is the same failure documented in the FTP and HTTP labs. It is a property of the dataset's age and will affect every remaining log in the capture.

**Problem 2 — Column mapping.**

Zeek's `ssh.log` schema changed between Bro 2.x and modern Zeek. The 2012-era format carried `status`, `direction`, `client`, `server`, `resp_size` — eleven columns. Modern Zeek carries eighteen, with `auth_success` and `auth_attempts` replacing `status`.

Getting this wrong is not obvious from the output. A wrong schema still populates `src_ip` and `dest_ip` correctly, because those are columns 3 and 5 in both versions — everything after `dest_port` shifts silently. The schema was confirmed against the file's own declaration before writing the extraction:

```bash
grep '^#fields' ssh.log
```

**Problem 3 — Header lines indexed as events.**

The `#separator`, `#fields`, and `#types` lines at the top of the file were ingested as data, inflating counts and polluting `stats` output. Excluded at search time with `NOT _raw="#*"`.

**Final configuration.**

`transforms.conf`:

```
[zeek_ssh_fields]
DELIMS = "\t"
FIELDS = "ts","uid","src_ip","src_port","dest_ip","dest_port","version","auth_success","auth_attempts","direction","client","server","cipher_alg","mac_alg","compression_alg","kex_alg","host_key_alg","host_key"
```

`props.conf`:

```
[ssh]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = ^
TIME_FORMAT = %s.%6N
MAX_TIMESTAMP_LOOKAHEAD = 20
TZ = UTC
MAX_DAYS_AGO = 10951
REPORT-ssh_fields = zeek_ssh_fields
```

Delimiter-based extraction was chosen over regex: Zeek TSV has a fixed column order, so `DELIMS` is both cleaner and faster than pattern matching. Zeek's native `id.orig_h` and `id.resp_h` were mapped to `src_ip` and `dest_ip` to avoid quoting dotted field names in every search and to align with Splunk's CIM.

Ingested via CLI rather than the web wizard, which re-detects sourcetype and silently overrides the custom stanza:

```bash
splunk add oneshot ssh.log -index ssh_log -sourcetype ssh
```

📷 `screenshots/field-extraction.png`

### 2. Baseline

```
index=ssh_log sourcetype=ssh earliest=0
| stats count, dc(src_ip) as sources, dc(dest_ip) as targets,
        min(_time) as first, max(_time) as last
| convert ctime(first) ctime(last)
```

| Metric | Value |
|---|---|
| Sessions | 7,143 |
| Distinct sources | 49 |
| Distinct targets | 58 |
| First event | 2012-03-16 07:30:11.840 |
| Last event | 2012-03-17 15:56:33.040 |

Note the scale relative to the HTTP capture: 7,143 events against 2,048,442. SSH is a quiet protocol, and no sampling was required. That quietness is analytically useful — 2,380 sessions from a single host is invisible inside two million HTTP requests and unmissable inside seven thousand SSH sessions.

📷 `screenshots/baseline.png`

### 3. The fields that were not there

Three fields in the modern Zeek schema returned empty or near-empty across the entire capture:

| Field | State | Cause |
|---|---|---|
| `user` | **Does not exist** | No username column in `ssh.log`, in any Zeek version |
| `auth_success` | Largely `-` | Inferred heuristically; requires the session to pass key exchange |
| `auth_attempts` | Largely `-` | Same |
| `client` / `server` | Largely `-` | Version banner never exchanged on incomplete sessions |

`user` is a hard limit of the protocol. SSH negotiates encryption before authentication, so the username travels inside the encrypted channel and a packet-based sensor cannot recover it. No configuration change produces this field.

`auth_success` and `auth_attempts` are a softer limit, and the emptiness is itself a measurement. Zeek can only count authentication attempts it observes, which requires the connection to progress past key exchange. That these fields are mostly unset across 7,143 sessions indicates that most connections in this capture never reached the authentication stage — consistent with the scanning behaviour documented in Finding 2.

The empty `client` field is the sharpest contrast with the HTTP work. There, DirBuster, Nmap NSE, and Nessus all named themselves in the User-Agent and the tools were identified in a single query. Here the equivalent field is blank, and every tool had to be identified by behaviour alone.

### 4. Behavioural classification

With no payload, no credentials, and no tool identifiers, the analysis rests on one ratio: **sessions divided by distinct targets.**

```
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| stats count as sessions, dc(dest_ip) as targets by src_ip
| eval per_target = round(sessions/targets, 1)
| eval profile = case(targets=1 AND sessions>100, "brute_force",
                      per_target<5 AND targets>10, "scan",
                      per_target>=5 AND targets>10, "sweep_then_attack",
                      targets<=10, "low_volume",
                      true(), "other")
| sort - sessions
```

| Source | Sessions | Targets | Per target | Profile |
|---|---|---|---|---|
| `192.168.202.141` | 2380 | 1 | 2380.0 | **brute_force** |
| `192.168.202.110` | 986 | 38 | 25.9 | sweep_then_attack |
| `192.168.202.140` | 894 | 38 | 23.5 | sweep_then_attack |
| `192.168.204.45` | 839 | 48 | 17.5 | sweep_then_attack |
| `192.168.202.79` | 274 | 44 | 6.2 | sweep_then_attack |
| `192.168.202.138` | 237 | 15 | 15.8 | sweep_then_attack |
| `192.168.202.109` | 220 | 17 | 12.9 | sweep_then_attack |
| `192.168.202.108` | 189 | 33 | 5.7 | sweep_then_attack |
| `192.168.202.68` | 176 | 48 | 3.7 | scan |
| `192.168.203.45` | 166 | 23 | 7.2 | sweep_then_attack |
| `192.168.202.112` | 116 | 25 | 4.6 | scan |
| `192.168.202.90` | 101 | 34 | 3.0 | scan |
| `192.168.202.80` | 66 | 16 | 4.1 | scan |
| `192.168.202.4` | 52 | 39 | 1.3 | scan |
| `192.168.202.87` | 51 | 20 | 2.6 | scan |
| `192.168.202.136` | 41 | 16 | 2.6 | scan |
| `192.168.202.95` | 40 | 13 | 3.1 | scan |
| `192.168.202.102` | 37 | 22 | 1.7 | scan |
| `192.168.202.100` | 28 | 8 | 3.5 | low_volume |

**The two columns say different things and must be read together.** High sessions against one target is a credential attack. Low sessions across many targets is enumeration — touch each host, note whether SSH answers, move on. Neither column alone separates them: `192.168.202.141` and `192.168.202.110` differ by a factor of 2.4 in session count and by a factor of 92 in intent.

The classifier was calibrated once. An initial threshold of `targets > 20` for the scan bucket misclassified `192.168.202.80` (16 targets) and `192.168.202.87` (20 targets) as low volume. Lowering it to 10 corrected both and surfaced four further scanners that had been falling through.

📷 `screenshots/source-profiles.png`

### 5. Timeline

```
index=ssh_log sourcetype=ssh earliest=0 | timechart span=1h count | sort - count
```

| Window | Sessions |
|---|---|
| **2012-03-17 14:00** | **2,410** |
| All other hours combined | 4,733 |

A single hour holds 33.7% of the entire capture. `192.168.202.141` generated 2,380 sessions in total, so essentially the whole spike is one host. There is no plateau and no ramp — the protocol's baseline activity is low tens of sessions per hour, and this is two orders of magnitude above it.

📷 `screenshots/timeline.png`

---

## Findings

### 🔴 Finding 1 — Sustained brute-force against a single host

**Source:** `192.168.202.141` → **Target:** `192.168.229.101`

| Metric | Value |
|---|---|
| Sessions | 2,380 |
| Distinct targets | **1** |
| Share of all traffic | 33.3% |
| Share of target's traffic | 97.4% |
| Peak hour | 2012-03-17 14:00 |

This host opened 2,380 SSH connections and contacted nothing else. The ratio is the finding: a per-target value of 2,380.0 has no legitimate equivalent. Administrative access does not require thousands of separate sessions to one machine, and a scanner does not stop at one target.

**The target is anomalous on its own terms.** `192.168.229.101` sits outside the `192.168.21–28.x` range that contains every other target in the capture, and it received 2,444 sessions — roughly ten times the next-busiest host.

```
index=ssh_log sourcetype=ssh earliest=0 dest_ip="192.168.229.101"
| stats count by src_ip | sort - count
```

| Source | Sessions | Share |
|---|---|---|
| `192.168.202.141` | 2380 | 97.4% |
| `192.168.202.110` | 32 | 1.3% |
| `192.168.202.79` | 19 | 0.8% |
| `192.168.202.125` | 4 | 0.2% |
| `192.168.203.45` | 4 | 0.2% |
| `192.168.202.136` | 1 | <0.1% |
| `192.168.202.143` | 1 | <0.1% |
| `192.168.202.94` | 1 | <0.1% |
| `192.168.203.63` | 1 | <0.1% |
| *(one further source)* | 1 | <0.1% |

> ⚠️ The final two rows were truncated in the original output. `dc(src_ip)` returned 10 and the eight confirmed counts sum to 2,442 of 2,444, so both remaining sources contributed one session each. Re-run and confirm before submission.

**The distribution is the interesting part.** Six of ten sources contacted this host once, consistent with incidental contact during a broader sweep. Two sources — `192.168.202.110` and `192.168.202.79`, both classified sweep_then_attack — probed at 32 and 19 sessions, more than a scan and far short of sustained effort. Then one host committed 2,380.

This is a staged sequence. Broad reconnaissance identifies the host, a small number of sources probe it, and one returns to attack it in volume.

**Outcome: unconfirmed.** `auth_success` was unset for this traffic, so whether any attempt succeeded cannot be determined from `ssh.log`. The activity is unambiguous; the result is not.

**Recommended action:** Isolate `192.168.202.141`. Review `/var/log/auth.log` on `192.168.229.101` for 2012-03-17 14:00 — that is where success or failure is recorded. Establish why this host sits in a subnet of its own and what it serves; it was singled out for a reason that this log does not contain.

📷 `screenshots/bruteforce-141.png`

### 🟠 Finding 2 — Network-wide reconnaissance sweep

**Widest source:** `192.168.202.68` — 48 distinct targets, 176 sessions, 3.7 per target

Nine hosts show the enumeration profile: many targets, few sessions each, no sustained effort anywhere. `192.168.202.68` reached 48 of the 58 targets in the capture — 83% of every SSH-reachable host in the environment — at under four sessions each.

`192.168.202.4` is the purest example at 1.3 sessions per target across 39 hosts. That is a single connection to each machine, which is exactly what a service sweep looks like: connect, observe whether SSH answers, record, disconnect.

**This is the phase that produced the target list for everything else.** `192.168.202.110` and `192.168.202.79`, the two hosts that probed `192.168.229.101` before the brute force, are both sweep_then_attack — they enumerated first and concentrated second.

**Outcome: successful.** Reconnaissance does not fail in the way an attack fails. Every host that answered on port 22 was found, and the subsequent concentration of effort demonstrates the results were used.

**Recommended action:** SSH connection attempts to more than a handful of internal hosts from a single source, within a short window, is a detection that requires only source and destination address. No field extraction beyond the first five columns is needed and it would have flagged nine hosts here.

📷 `screenshots/recon-sweep.png`

### 🟠 Finding 3 — Infrastructure addresses targeted by role

```
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| stats count as sessions, dc(src_ip) as attackers by dest_ip
| sort - attackers
```

| Target | Sessions | Distinct attackers |
|---|---|---|
| `192.168.24.253` | 155 | 23 |
| `192.168.25.253` | 125 | 23 |
| `192.168.28.253` | 138 | 22 |
| `192.168.21.253` | 244 | 21 |
| `192.168.22.253` | 174 | 21 |
| `192.168.23.253` | 143 | 18 |
| `192.168.25.203` | 105 | 18 |
| `192.168.27.253` | 138 | 17 |
| `192.168.23.203` | 126 | 16 |
| `192.168.27.254` | 118 | 16 |

**The host address `.253` appears in eight separate subnets, each drawing between 13 and 23 distinct attackers.** That is not eight coincidences. In a consistently addressed environment, `.253` is a gateway, router, or management interface, and attackers pursued the role across every segment rather than working through hosts individually.

Secondary clusters at `.254`, `.203`, `.202`, `.101`, and `.102` indicate the same addressing convention — infrastructure high in the range, servers in the middle, workstations below.

This mirrors the `/main.php` result in the HTTP analysis: the CCDC pattern, where every competing team runs identical infrastructure, so one path or one host address is not a single target but a template replicated environment-wide.

**Recommended action:** Infrastructure addresses should not accept SSH from general workstation ranges. Segment the management plane.

📷 `screenshots/infrastructure-targeting.png`

### 🟠 Finding 4 — Every session crossed a segment boundary

| | Range |
|---|---|
| All sources | `192.168.202.x`, `192.168.203.x`, `192.168.204.x` |
| All targets | `192.168.21–28.x`, plus `192.168.229.101` |

**Not one session in 7,143 stayed within a single range.** Every source sat in the 202–204 block and every target outside it.

This is the most operationally useful finding in the report and the cheapest to detect. It requires two fields, both of which survive encryption, and it would have flagged every attacking host in the capture — the brute-forcer, all nine scanners, all eight sweep-then-attack hosts — without distinguishing between them or needing to.

```
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| eval src_net=mvindex(split(src_ip,"."),2), dest_net=mvindex(split(dest_ip,"."),2)
| eval crossed=if(src_net=dest_net,"same_segment","cross_segment")
| stats count by crossed
```

**Recommended action:** Alert on SSH crossing segment boundaries where no administrative relationship exists. In an environment with a defined management plane this is a low-noise, high-yield rule.

### 🟢 Finding 5 — Analysis errors caught and corrected

**Sorting by attacker count concealed the largest target.**

Ranking targets by `dc(src_ip)` placed `192.168.21.253` at the top with 244 sessions from 21 sources. That view omitted `192.168.229.101` entirely — 2,444 sessions, ten times the traffic, contacted by only 10 sources.

Re-running the identical search sorted by session volume surfaced it immediately:

```
| stats count as sessions, dc(src_ip) as attackers by dest_ip
| sort - sessions      ← the only change
```

The two sorts answer different questions. Breadth finds hosts that many attackers considered worth touching. Depth finds hosts that one attacker considered worth committing to. **A concentrated attack is invisible to the first and obvious to the second**, and the most serious incident in this capture was the concentrated kind.

**A classifier threshold set too high.**

The initial behavioural rule required `targets > 20` to classify a source as scanning. `192.168.202.80` (16 targets) and `192.168.202.87` (20 targets) fell through to low volume despite per-target ratios of 4.1 and 2.6 — unambiguous enumeration profiles. Lowering the threshold to 10 corrected both and surfaced four additional scanners below them that the original rule had been discarding.

**Why this section exists:** Both errors produced output that looked correct. The first table was well-formed and its top entry was genuinely under attack; the second classified fifteen hosts accurately and two wrongly. Neither failure announced itself, and both were found by asking whether the question had been framed correctly rather than whether the query had run.

---

## Summary

| Finding | Host | Outcome | Severity |
|---|---|---|---|
| Brute-force, 2,380 sessions, single target | `192.168.202.141` | Unconfirmed | **High** |
| Network-wide reconnaissance, 48 targets | `192.168.202.68` (+8) | **Successful** | Medium |
| Infrastructure targeting, `.253` across 8 subnets | Multiple | Partial | Medium |
| Segment-crossing SSH, all 7,143 sessions | All 49 sources | — | Medium |
| Sweep-then-concentrate against `192.168.229.101` | `.202.110`, `.202.79` | Unconfirmed | Medium |

---

## Lessons Learned

**Sort order is a hypothesis.** Ranking targets by attacker count and by session count are the same query with one word changed, and they return different answers to different questions. The first buried the most-attacked host in the dataset. Choosing a sort is choosing what kind of attack you are willing to find, and it is worth running both.

**Ratios separate intent; volume does not.** `192.168.202.141` and `192.168.202.110` are the two busiest hosts in the capture and they were doing entirely different things. Session count ranked them adjacently. Sessions per target separated them by a factor of 92. Where content is unavailable, the relationship between two counts carries the information that a payload would otherwise carry.

**Empty fields are measurements.** `auth_attempts` being unset across most of the capture was initially treated as an extraction bug and investigated as one — schema version, column alignment, delimiter handling, all checked. The field was correct and genuinely empty, and the emptiness meant most connections never reached authentication. That is a finding about scanning volume, arrived at by failing to fix something that was not broken.

**Know what your log cannot tell you.** The HTTP analysis identified DirBuster, Nmap NSE, and Nessus from a single User-Agent query. The equivalent SSH field is blank on nearly every session, and no tool in this capture was ever named. SSH encrypts before it authenticates, so usernames, commands, and credentials are permanently out of reach of a network sensor. Stating that boundary is more useful than guessing past it, and it identifies exactly which log source resolves the question: `/var/log/auth.log` on the targets.

**Calibrate thresholds against the data, not against intuition.** `targets > 20` seemed a reasonable definition of scanning and silently misclassified six hosts. Running the classifier without its filter first, looking at where the natural break falls, and setting the threshold there would have caught it immediately.

**The cheapest detection was the best one.** Every attacking host in this capture crossed a network segment boundary, using two fields that encryption cannot hide. No field extraction beyond column five, no payload inspection, no behavioural modelling. The sophisticated analysis in this report describes what the attackers were doing; the trivial one would have stopped all of them.

**A quiet protocol is an advantage.** 7,143 SSH sessions against 2,048,442 HTTP requests in the same capture. No sampling was required, every event was analyzed, and a single host generating 2,380 sessions was impossible to miss. The same activity inside the HTTP log would have been a rounding error.

---

## Appendix — Key Queries

```
# Baseline and time span
index=ssh_log sourcetype=ssh earliest=0
| stats count, dc(src_ip) as sources, dc(dest_ip) as targets,
        min(_time) as first, max(_time) as last
| convert ctime(first) ctime(last)

# Confirm timestamps parsed to 2012 and fields populated
index=ssh_log sourcetype=ssh earliest=0
| head 5 | table _time, src_ip, dest_ip, version, direction

# Which fields actually carry data
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| fieldsummary | table field, count, distinct_count, values

# Verify column count against the schema
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| head 1
| eval cols = 1 + len(_raw) - len(replace(_raw, "\t", ""))
| table cols

# Top sources and destinations
index=ssh_log sourcetype=ssh earliest=0 | top limit=10 src_ip
index=ssh_log sourcetype=ssh earliest=0 | top limit=10 dest_ip

# Traffic shape over time
index=ssh_log sourcetype=ssh earliest=0 | timechart span=1h count

# Peak interval
index=ssh_log sourcetype=ssh earliest=0
| timechart span=1h count | sort - count

# Behavioural classification — the core query
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| stats count as sessions, dc(dest_ip) as targets by src_ip
| eval per_target = round(sessions/targets, 1)
| eval profile = case(targets=1 AND sessions>100, "brute_force",
                      per_target<5 AND targets>10, "scan",
                      per_target>=5 AND targets>10, "sweep_then_attack",
                      targets<=10, "low_volume",
                      true(), "other")
| sort - sessions

# Targets by breadth — how many attackers touched each host
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| stats count as sessions, dc(src_ip) as attackers by dest_ip
| sort - attackers

# Targets by depth — the same query that found 192.168.229.101
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| stats count as sessions, dc(src_ip) as attackers by dest_ip
| sort - sessions

# Drill into a single target
index=ssh_log sourcetype=ssh earliest=0 dest_ip="192.168.229.101"
| stats count by src_ip | sort - count

# Drill into a single source
index=ssh_log sourcetype=ssh earliest=0 src_ip="192.168.202.110"
| stats count by dest_ip | sort - count

# Segment-boundary crossing
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| eval src_net=mvindex(split(src_ip,"."),2), dest_net=mvindex(split(dest_ip,"."),2)
| eval crossed=if(src_net=dest_net,"same_segment","cross_segment")
| stats count by src_ip, crossed | sort - count

# Per-host session timing — separates tools from operators
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| stats min(_time) as first_seen, max(_time) as last_seen,
        count as sessions, dc(dest_ip) as targets by src_ip
| eval duration_min = round((last_seen-first_seen)/60,1)
| eval rate = round(sessions/(duration_min+1),1)
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen

# Crypto negotiation — sparse in this capture, useful where populated
index=ssh_log sourcetype=ssh earliest=0 NOT _raw="#*"
| stats count by cipher_alg, kex_alg | sort - count
```****
