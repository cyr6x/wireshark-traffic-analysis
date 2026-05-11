# Wireshark Traffic Analysis Lab
**Malicious PCAP Analysis | IOC Extraction | Threat Brief**

> A hands-on cybersecurity lab demonstrating network traffic analysis using Wireshark to identify malicious activity, extract Indicators of Compromise (IOCs), and produce a structured threat brief — simulating the daily workflow of a SOC Tier-1 analyst.

---

## Why This Matters

Network traffic analysis is a core SOC analyst skill. When an alert fires in a SIEM, analysts must pivot into raw packet data to confirm whether it’s a true positive, identify what the attacker did, and extract IOCs to block further damage. This lab replicates that workflow end-to-end using a real-world malicious PCAP containing active C2 traffic.

---

## Lab Environment

| Component | Details |
|---|---|
| **Analysis Tool** | Wireshark 4.x |
| **PCAP Source** | [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html) — 2026-02-28 exercise |
| **Platform** | Kali Linux (isolated VM) |
| **Network** | Host-only / isolated — no live malicious traffic |

---

## Analysis Summary

| Field | Value |
|---|---|
| **PCAP File** | 2026-02-28-traffic-analysis-exercise.pcap |
| **Infected Host IP** | 10.2.28.88 |
| **Infected Host MAC** | 00:19:d1:b2:4d:ad (Intel NIC) |
| **Infected Host OS** | Windows NT (from server response header) |
| **Malware Family** | NetSupport RAT |
| **C2 IP** | 45.131.214.85 |
| **C2 URL** | http://45.131.214.85/fakeurl.htm |
| **VirusTotal Detections** | 13/93 vendors flagged as malicious |
| **C2 Behavior** | Periodic HTTP POST beaconing every ~60 seconds |

---

## Attack Timeline

| Time (Relative) | Event |
|---|---|
| 0.000000s | DHCP Discover — infected host requests IP from network |
| 4.306185s | DHCP ACK — host assigned IP 10.2.28.88 by server 10.2.28.1 |
| ~9188s | First HTTP POST to 45.131.214.85/fakeurl.htm observed |
| ~9188s+ | Repeated C2 beaconing begins — POST every ~60 seconds |
| Ongoing | Encoded data (`CMD=ENCD`, `DATA=...`) sent back to infected host |

---

## Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| **C2 IP** | 45.131.214.85 | 13/93 vendors flagged malicious on VirusTotal |
| **C2 URL** | http://45.131.214.85/fakeurl.htm | NetSupport RAT callback URL |
| **User-Agent** | `NetSupport Manager/1.3` | Hardcoded RAT user-agent string |
| **C2 Commands** | `CMD=POLL`, `CMD=ENCD` | NetSupport RAT polling and encoded command protocol |
| **Server Header** | `NetSupport Gateway/1.92 (Windows NT)` | Attacker’s C2 server fingerprint |
| **Infected Host IP** | 10.2.28.88 | Internal host performing all C2 callbacks |
| **Infected Host MAC** | 00:19:d1:b2:4d:ad | Intel NIC — from Ethernet frame headers |

---

## Wireshark Filters Used

```wireshark
# Identify all HTTP requests
http.request

# All DNS lookups
dns

# Isolate all C2 traffic
ip.addr == 45.131.214.85

# Detect SYN scans
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Follow HTTP Stream (right-click any HTTP packet)
# Reveals: User-Agent, CMD=POLL, CMD=ENCD, DATA payload
```

---

## What NetSupport RAT Does

NetSupport RAT is a legitimate remote administration tool (NetSupport Manager) abused by threat actors as malware. Once installed on a victim machine it:

- **Beacons** to the C2 server over HTTP POST at regular intervals (`CMD=POLL`)
- **Receives encoded commands** from the attacker (`CMD=ENCD` + `DATA=` field)
- **Provides full remote control** — keylogging, screen capture, file transfer, command execution
- **Blends in** by using a legitimate tool’s User-Agent and HTTP traffic pattern, making it harder to detect without deep packet inspection

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing / Drive-by Compromise | T1566 / T1189 |
| Execution | User Execution: Malicious File | T1204.002 |
| Persistence | Remote Access Software | T1219 |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Command & Control | Non-Standard Port (HTTP on 80 to external IP) | T1571 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

---

## Screenshots

```
screenshots/
├── 01-dhcp-host-ip.png          # DHCP ACK assigning 10.2.28.88
├── 02-dns-queries.png           # DNS filter results
├── 03-http-post-c2.png          # ip.addr == 45.131.214.85 repeated POST traffic
├── 04-follow-http-stream.png    # HTTP stream showing CMD=POLL, User-Agent, DATA
└── 05-virustotal-ip-check.png   # VirusTotal result: 13/93 vendors flagged
```

> ⚠️ **PCAP not included** — contains live malicious content. Source: [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html)

---

## Defender Takeaways

### What the attacker was doing
- Infected host was running NetSupport RAT, silently beaconing to attacker C2 every ~60 seconds
- Encoded commands were being sent from C2 to the infected machine — full remote control established
- Traffic used legitimate-looking HTTP on port 80, making it blend with normal web traffic

### How a SOC analyst detects this
| Signal | Detection Logic |
|---|---|
| **Unusual User-Agent** | `NetSupport Manager/1.3` is never legitimate browser traffic — alert on this string |
| **Beaconing pattern** | Same external IP hit via POST every ~60s — SIEM rule: >10 POSTs to same external IP/hour |
| **`/fakeurl.htm` path** | No legitimate site uses this path — alert on HTTP requests containing `fakeurl` |
| **No DNS resolution before connection** | Host connected directly to IP, bypassing DNS — flag direct-IP HTTP outbound connections |
| **`CMD=POLL` in POST body** | Content inspection rule in web proxy or IDS/IPS |

### Controls that would prevent this
| Control | How It Helps |
|---|---|
| **Web Proxy + SSL Inspection** | Intercepts HTTP/S traffic, can block unknown external IPs and inspect POST bodies |
| **EDR (e.g. CrowdStrike, Defender for Endpoint)** | Detects NetSupport Manager running outside approved software list |
| **Application Whitelisting** | Blocks unauthorized executables — NetSupport Manager not on the approved list = blocked |
| **Egress Filtering** | Block outbound HTTP to raw IPs (no domain) — eliminates this entire C2 channel |
| **SIEM Correlation Rule** | `User-Agent contains NetSupport` OR `POST to external IP > 10/hour` → P1 alert |

---

## Academic & Professional Context

- **CompTIA Security+ SY0-701** — Domain 4.9: Use data sources to support an investigation
- **NIST SP 800-61** — Incident Response Phase 2: Detection & Analysis
- **SOC Tier-1 duties** — Alert triage, PCAP review, IOC extraction, threat brief production

---

## Status

- [x] Lab environment configured
- [x] PCAP downloaded and analysed
- [x] Infected host identified (10.2.28.88)
- [x] C2 traffic isolated and confirmed (45.131.214.85)
- [x] HTTP stream followed — NetSupport RAT confirmed
- [x] IOCs extracted and documented
- [x] VirusTotal verification completed (13/93)
- [x] MITRE ATT&CK mapping finalised
- [ ] Screenshots added to `/screenshots`
