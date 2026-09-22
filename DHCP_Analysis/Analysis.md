# DHCP Log Analysis

**Objective:** Ingest Bro/Zeek DHCP logs into Splunk, build field extractions, and profile how IP addresses were assigned across the network, separating normal client behaviour from misconfiguration, address churn, and abuse.

**Dataset:** `dhcp.log` from the MACCDC 2012 capture
**Index:** `dhcp_log` | **Sourcetype:** `dhcp`
**Events analyzed:** 1,502 (full file), covering 07:00 2012-03-16 – 15:59 2012-03-17

---

## Why DHCP?

DHCP is one of the quietest protocols on a network, and that is exactly what makes it useful. Every device that joins the network has to ask for an address, and the answer is logged. Three properties make it worth analyzing:

- **It is the network's guest book.** A DHCP lease ties a hardware address (MAC) to a network address (IP) at a specific time. When another log shows suspicious activity from an IP, DHCP is how you find out which physical device held that IP at that moment.
- **Normal behaviour is boring and predictable.** A healthy client requests a lease, renews it occasionally, and otherwise stays quiet. Anything chatty, anything that keeps changing addresses, and anything that appears in bursts stands out immediately.
- **It is easy to abuse.** DHCP has no authentication. Starvation attacks (exhausting the address pool with fake MACs), rogue servers, and MAC spoofing all leave traces here — and so do their absence.

---

## Methodology

### 1. Ingestion

`transforms.conf`:

```ini
[dhcp_transform]
REGEX = ^#
DEST_KEY = queue
FORMAT = nullQueue

[bro_dhcp_fields]
DELIMS = "\t"
FIELDS = "ts","uid","src_ip","src_port","dest_ip","dest_port","mac","assigned_ip","lease_time","trans_id"
```

`props.conf`:

```ini
[dhcp]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = ^
TIME_FORMAT = %s.%6N
MAX_TIMESTAMP_LOOKAHEAD = 20
TZ = UTC
MAX_DAYS_AGO = 10951
MAX_DAYS_HENCE = 2
TRANSFORMS = dhcp_transform
REPORT-bro_dhcp_fields = bro_dhcp_fields
```



### 2. Client activity

```
index=dhcp_log sourcetype=dhcp | stats count by mac | sort - count
```

| MAC | Events | Note |
|---|---|---|
| 00:26:9e:83:a2:30 | 744 | ~8x the next client — see Finding 1 |
| 00:23:54:8a:21:78 | 94 | |
| 00:24:54:eb:dc:f2 | 79 | |
| 08:11:96:8d:be:84 | 51 | |
| f0:de:f1:2e:6a:5a | 42 | |
| 00:0c:29:25:61:e1 | 39 | VMware virtual machine |
| 00:0c:29:98:25:c1 | 35 | VMware virtual machine |

The distribution is not a curve, it is a cliff. One client sits at 744 events and the rest of the network falls off to double digits almost immediately.

Several MACs begin with `00:0c:29`, the prefix VMware assigns to virtual network adapters. At least six virtual machines appear in the data, which is consistent with a competition environment built on virtualized infrastructure.



### 3. Timeline

```
index=dhcp_log sourcetype=dhcp | timechart span=1h count
```

| Window | Activity |
|---|---|
| 2012-03-16 07:00 – 17:59 | 811 events, 35 – 108 per hour |
| 2012-03-16 18:00 – 2012-03-17 06:59 | **Zero events** |
| 2012-03-17 07:00 – 15:59 | 691 events, 37 – 117 per hour |

The network has a hard on/off schedule. Activity starts at 07:00, stops at 18:00, and for thirteen hours overnight not a single DHCP message is logged. Real office networks never go fully silent — laptops sleep, servers renew, phones reconnect. Total silence means the network itself was powered down or the capture was paused outside competition hours.

The busiest hours were 08:00 on day 1 (108 events) and 14:00 on day 2 (117 events). The quietest active hour was 10:00 on day 1 (35 events). Section 4 shows that the busiest hours are misleading until the dominant client is removed.



### 4. Removing the dominant client

One client produced 744 of 1,502 events — **49.5% of all DHCP traffic**. Any network-wide chart is therefore half a chart of that single device. Subtracting it reveals what the rest of the network was actually doing:

```
index=dhcp_log sourcetype=dhcp mac!="00:26:9e:83:a2:30" | timechart span=1h count
```

| Hour | All clients | Dominant client | Everyone else |
|---|---|---|---|
| 03-16 07:00 | 81 | 24 | 57 |
| 03-16 08:00 | 108 | 47 | 61 |
| 03-16 10:00 | 35 | 17 | 18 |
| 03-16 15:00 | 68 | 46 | 22 |
| 03-17 08:00 | 99 | 41 | 58 |
| 03-17 11:00 | 63 | 42 | 21 |
| 03-17 14:00 | 117 | 43 | **74** |

Two things change once the noise is removed:

- **The real peak moves.** For the rest of the network, the busiest hour of the whole capture is 14:00 on day 2 (74 events), noticeably higher than any other hour. Something caused many devices to request addresses at once — a batch of machines rebooting, reconnecting, or being brought online.
- **The morning start-up becomes visible.** Both days open with the rest of the network at its highest levels (57 – 61 events at 07:00 – 08:00), which is what a room full of machines booting at the start of the day looks like.

The 10:00 dip on day 1 affected everyone: the dominant client and the rest of the network both dropped to roughly a third of their normal rate in the same hour. A network-wide dip across unrelated devices points to an infrastructure event (the DHCP server, a switch, or the capture sensor), not to any one client.



---

## Findings

### 🟠 Finding 1 — One client generating half of all DHCP traffic

**MAC:** `00:26:9e:83:a2:30` → **IP:** `192.168.202.76`

| Metric | Value |
|---|---|
| Events | 744 |
| Share of all DHCP traffic | 49.5% |
| Unique IPs received | 1 |
| Rate | 40 – 47 per hour (≈ one every 80 seconds) |
| Events with a 24-hour lease | 5 |
| Events with no lease time recorded | 739 |

```
index=dhcp_log sourcetype=dhcp mac="00:26:9e:83:a2:30" | stats count by assigned_ip
index=dhcp_log sourcetype=dhcp mac="00:26:9e:83:a2:30" | stats count by lease_time
index=dhcp_log sourcetype=dhcp mac="00:26:9e:83:a2:30" | timechart span=1h count
```

The device held the same address, 192.168.202.76, for the entire capture. It received a normal 24-hour lease (`lease_time = 86400`) five times. A client with a 24-hour lease should need to speak to the DHCP server roughly once or twice a day. This one did so 744 times.

The `lease_time` of `0` on the other 739 events does not mean a zero-second lease. It means the server's reply carried no lease time at all. That pattern fits a client that already has its address and keeps asking the server for other configuration settings, rather than requesting or renewing a lease.

The hourly chart is flat: 40 – 47 requests every hour, both days, with no ramp-up or decay. That regularity is the signature of software on a timer, not a person.

**Outcome:** Misconfiguration or automated behaviour, not an address-pool attack. The device never requested a second IP, so it was not exhausting the pool.

**Recommended action:** Identify the host behind 192.168.202.76 and review its network configuration and running services. Pull a packet capture of its DHCP traffic to see the exact message types it is sending (see Lessons Learned).



### 🟡 Finding 2 — Address churn on a single client

**MAC:** `00:c0:ca:39:09:1e`

```
index=dhcp_log sourcetype=dhcp mac="00:c0:ca:39:09:1e" | table _time assigned_ip
```

| Time | Assigned IP |
|---|---|
| 03-16 13:04:57 | 192.168.202.124 |
| 03-16 13:07:51 | 192.168.202.124 |
| 03-16 15:09:19 | 192.168.202.130 |
| 03-16 15:55:30 | 192.168.202.132 |
| 03-16 16:01:38 | 192.168.202.133 |
| 03-16 16:10:55 | 192.168.202.133 |
| 03-17 07:36:03 | 192.168.202.133 |
| 03-17 08:30:46 | 192.168.202.133 |
| 03-17 08:40:23 | 192.168.202.133 |
| 03-17 09:07:52 | 192.168.202.133 |

Four different addresses in three hours, each one higher than the last. DHCP servers generally hand out the next free address in the pool, so an upward staircase like this means the client kept arriving as if it were new — disconnecting long enough to lose its lease, or releasing it and asking again.

After 16:01 on day 1 the churn stops. The client held .133 for the rest of the capture, including across the overnight shutdown.

A follow-up search confirmed that .133 was never assigned to any other device:

```
index=dhcp_log sourcetype=dhcp assigned_ip="192.168.202.133" | stats count by mac
```

| MAC | Count |
|---|---|
| 00:c0:ca:39:09:1e | 6 |

**Outcome:** Unstable connectivity during one afternoon, then stable. No address conflict.

**Recommended action:** Low priority. If the device is wireless, check signal and roaming behaviour for the 13:00 – 16:00 window on day 1. Keep in mind that any activity from .124, .130, or .132 on day 1 belongs to this device, not to whatever held those addresses later.


### 🟡 Finding 3 — Clients holding more than one address

```
index=dhcp_log sourcetype=dhcp | stats dc(assigned_ip) as ip_count by mac | where ip_count > 1
```

| MAC | Unique IPs |
|---|---|
| 00:c0:ca:39:09:1e | 4 |
| 00:0c:29:4e:9e:86 | 2 |
| 00:1e:68:bd:38:ee | 2 |
| 00:c0:ca:5f:68:69 | 2 |
| 3c:07:54:1c:a6:65 | 2 |
| 5c:26:0a:6a:40:84 | 2 |
| a0:88:b4:ae:26:4c | 2 |
| b8:8d:12:53:a8:d8 | 2 |
| bc:ae:c5:9e:f3:b6 | 2 |
| c4:2c:03:30:73:33 | 2 |

Ten clients changed address at least once. Nine of them changed exactly once, which is ordinary: a lease expired, or a machine was off long enough (the overnight shutdown alone is thirteen hours) to be given a new one in the morning. Only Finding 2 is an outlier.

`bc:ae:c5:9e:f3:b6` appears both here and in the top-talker list (17 events), making it the next most interesting client after Finding 2.

**Outcome:** Mostly normal lease turnover.

**Recommended action:** When correlating these IPs against other logs, always check which MAC held the address at the time of the event. For these ten clients, "the IP" and "the device" are not the same thing across the whole capture.


### 🟢 Finding 4 — Anomalies investigated and ruled out

**DHCP starvation.**
A client generating half of all DHCP traffic is the first thing a starvation attack would look like. It was ruled out: a starvation attack uses many fake MACs to claim many addresses. Finding 1 is one MAC holding one address the entire time.

**IP conflict on 192.168.202.133.**
The address was investigated because the client in Finding 2 arrived at it after three changes. Only one MAC was ever assigned it.

**Overnight outage.**
Thirteen hours of zero traffic would normally suggest a failed server or sensor. Both days start and stop at the same hours, and clients kept their addresses across the gap (Finding 2's .133 survives the night). This is a scheduled shutdown matching competition hours, not a failure.

**Why this section exists:** each of these would trigger a simple alert — a chatty client, a changing address, a silent network. Each has an ordinary explanation. Proving which is which is the analysis.

---

## Summary

| Finding | Host | Assessment | Severity |
|---|---|---|---|
| Half of all DHCP traffic from one client | 00:26:9e:83:a2:30 / .202.76 | Misconfiguration or automation | Medium |
| Four addresses in three hours | 00:c0:ca:39:09:1e | Unstable connection, then stable | Low |
| Ten clients with multiple addresses | Multiple | Normal lease turnover | Low |
| Starvation, IP conflict, outage | — | Ruled out | Benign |

---

## Lessons Learned

**One device can be half the dataset.** The network-wide timeline looked like a busy network with a peak at 08:00. After removing a single client, the real peak moved to a different day and a different hour. Before reading any aggregate, check whether one source is dominating it.

**A zero is not always a value.** `lease_time = 0` looked like a zero-second lease. It actually meant "not present in this message." Reading a field correctly means knowing what the parser writes when data is missing.

**Sequential addresses tell a story.** .124 → .130 → .132 → .133 is not four random assignments. The steady upward order shows the server handing out the next free address to a client that kept coming back as new.

**Silence is data.** Thirteen hours of zero events is not an empty part of the chart; it tells you the network had a schedule. It also explains why several clients got new addresses the next morning.

**Configuration can fail quietly.** A props.conf stanza with a name that did not match the sourcetype produced no error at all. The data simply loaded wrong. btool confirmed which settings Splunk was actually using, which is faster than guessing.

**The log's schema limits the conclusions.** This version of Bro's `dhcp.log` records the MAC, the assigned IP, and the lease time, but not the DHCP message type (DISCOVER, REQUEST, INFORM, and so on). That is why Finding 1 can say the device is abnormally chatty but not exactly what it was asking for. A packet capture of that host's port 67/68 traffic would settle it.
