# Wireshark Traffic Analysis Lab
**Malicious PCAP Analysis | IOC Extraction | Threat Brief** 

> A hands-on cybersecurity lab demonstrating network traffic analysis using Wireshark to identify malicious activity, extract Indicators of Compromise (IOCs), and produce a structured threat brief — simulating the daily workflow of a SOC Tier-1 analyst.

---

## Why This Matters

Network traffic analysis is a core SOC analyst skill. When an alert fires in a SIEM, analysts must pivot into raw packet data to confirm whether it’s a true positive, identify what the attacker did, and extract IOCs to block further damage. This lab replicates that workflow end-to-end using real-world malicious PCAPs.

---

## Lab Environment

| Component | Details |
|---|---|
| **Analysis Tool** | Wireshark 4.x |
| **PCAP Source** | [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/tutorials/index.html) |
| **Platform** | Kali Linux (isolated VM) |
| **Network** | Host-only / isolated — no live malicious traffic |

---

## Objectives

- Identify infected hosts from raw packet captures
- Extract IOCs: malicious IPs, domains, URLs, and user-agents
- Reconstruct the attack timeline from packet timestamps
- Produce a threat brief matching real SOC deliverable standards
- Map findings to MITRE ATT&CK techniques

---

## Wireshark Filters Used

```wireshark
# Identify all HTTP requests (domains contacted)
http.request

# All DNS lookups (spot DGA/C2 domains)
dns

# Filter all traffic to/from a suspicious IP
ip.addr == <suspicious-IP>

# Detect SYN scans / connection attempts
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Hunt for credentials in plaintext
frame contains "password"

# Export HTTP objects (downloaded payloads)
# File > Export Objects > HTTP
```

---

## Analysis Summary

> 📌 **Fill this in during your analysis**

| Field | Value |
|---|---|
| **PCAP File** | *(filename from malware-traffic-analysis.net)* |
| **Infection Date/Time** | *(from Wireshark packet timestamps)* |
| **Infected Host IP** | *(e.g. 192.168.1.x)* |
| **Infected Host MAC** | *(from ARP/DHCP packets)* |
| **Infected Host OS** | *(from User-Agent string or DHCP hostname)* |
| **Malware Family** | *(identified from tutorial answer key)* |

---

## Attack Timeline

> 📌 **Reconstruct from packet timestamps**

| Time (UTC) | Event |
|---|---|
| HH:MM:SS | Infected host makes DNS lookup for suspicious domain |
| HH:MM:SS | HTTP GET request to malicious URL — payload download begins |
| HH:MM:SS | C2 beacon observed (periodic outbound connections) |
| HH:MM:SS | Data exfiltration or lateral movement detected |

---

## Indicators of Compromise (IOCs)

> 📌 **Extract from your PCAP analysis**

| Type | Value | Notes |
|---|---|---|
| **IP Address** | x.x.x.x | C2 server / malicious host |
| **Domain** | malicious-domain.com | Resolved in DNS query |
| **URL** | http://domain/path/payload.exe | Payload delivery URL |
| **User-Agent** | Mozilla/4.0 (unusual) | Malware-specific UA string |
| **File Hash (MD5)** | *(if payload exported)* | Exported HTTP object |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Drive-by Compromise | T1189 |
| Execution | User Execution: Malicious File | T1204.002 |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

> Map your specific findings to [attack.mitre.org](https://attack.mitre.org) and replace/add rows as needed.

---

## Screenshots

> Add screenshots to the `/screenshots` folder and reference them below.

```
screenshots/
├── 01-http-requests.png       # http.request filter results
├── 02-dns-lookups.png         # Suspicious DNS queries
├── 03-c2-traffic.png          # C2 beacon traffic
├── 04-ioc-summary.png         # IOC list / filter results
└── 05-exported-objects.png    # HTTP exported objects (payloads)
```

> ⚠️ **Do not push PCAP files** — they contain live malicious content. Reference by filename and link to source only.

---

## Tools & Resources

| Tool | Purpose | Link |
|---|---|---|
| Wireshark | Packet capture analysis | [wireshark.org](https://www.wireshark.org) |
| malware-traffic-analysis.net | Real-world malicious PCAPs + tutorials | [Link](https://www.malware-traffic-analysis.net/tutorials/index.html) |
| MITRE ATT&CK Navigator | Technique mapping | [attack.mitre.org](https://attack.mitre.org) |
| VirusTotal | IOC reputation checks | [virustotal.com](https://www.virustotal.com) |

---

## Defender Takeaways

### What the malware was doing
- Contacted external C2 infrastructure over HTTP (unencrypted, detectable)
- Used DNS to resolve randomised or fast-flux domains (DGA behaviour)
- Downloaded a secondary payload via HTTP GET

### What a SOC analyst should alert on
- **DNS anomalies** — high-entropy domain names, NX domain storms, unusually high DNS query rates
- **Beaconing patterns** — regular periodic outbound connections at fixed intervals to the same IP
- **Unusual User-Agent strings** — malware often uses hardcoded or outdated UA strings
- **HTTP downloads without a referrer** — payload pulls often have no `Referer` header

### Controls that would prevent / detect this
| Control | How It Helps |
|---|---|
| **DNS Filtering** (e.g. Cisco Umbrella) | Blocks C2 domain resolution before connection is made |
| **Web Proxy / SSL Inspection** | Intercepts and inspects HTTP/HTTPS traffic for malicious payloads |
| **EDR (e.g. CrowdStrike, Defender)** | Detects payload execution on endpoint before C2 callback |
| **SIEM Correlation Rules** | Correlates DNS + HTTP + process creation events into a single alert |
| **Network Segmentation** | Limits blast radius if a host is compromised |

---

## Academic & Professional Context

This lab maps directly to:
- **CompTIA Security+ SY0-701** — Domain 4.9 (Given a scenario, use data sources to support an investigation)
- **NIST SP 800-61** — Incident Response Phase 2: Detection & Analysis
- **SOC Analyst Tier-1 duties** — Alert triage, PCAP review, IOC extraction, initial threat brief

---

## Status

- [x] Lab environment configured
- [x] Wireshark filters documented
- [ ] PCAP downloaded and analysed
- [ ] IOCs extracted and documented
- [ ] Screenshots added to `/screenshots`
- [ ] Threat brief completed
- [ ] MITRE ATT&CK mapping finalised
