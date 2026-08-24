# Wireshark Traffic Analysis — NetSupport RAT C2

Forensic analysis of a malicious PCAP (from malware-traffic-analysis.net) to identify an infected host, isolate its C2 traffic, and produce an IOC list — the kind of triage a Tier-1 SOC analyst does on a flagged packet capture.

## What I found

Working from a DHCP lease and a run of HTTP POST requests, I traced an infected host (10.2.28.88) beaconing every ~60 seconds to 45.131.214.85/fakeurl.htm. Following the HTTP stream surfaced the hardcoded `NetSupport Manager/1.3` user-agent and the `CMD=POLL` / `CMD=ENCD` command protocol — confirming NetSupport RAT, a legitimate remote-admin tool commonly abused as a C2 channel. The C2 IP came back 13/93 malicious on VirusTotal.

## Method

1. `bootp or dhcp` — identify the infected host's IP/MAC from its DHCP lease
2. `dns` — check what it resolved before/after infection (direct-to-IP traffic with no prior DNS lookup is itself a signal)
3. `http.request` — isolate outbound HTTP; repeated POSTs to a raw IP stand out immediately
4. `ip.addr == 45.131.214.85` — confirm the ~60s beaconing pattern
5. Follow HTTP Stream on a POST packet — recover the C2 protocol and user-agent
6. Cross-check the C2 IP on VirusTotal

## IOCs

| Type | Value |
|---|---|
| C2 IP | 45.131.214.85 (13/93 on VirusTotal) |
| C2 URL | `http://45.131.214.85/fakeurl.htm` |
| User-Agent | `NetSupport Manager/1.3` |
| C2 commands | `CMD=POLL`, `CMD=ENCD` |

`[SCREENSHOT: HTTP stream showing the NetSupport user-agent and CMD=POLL traffic]`
`[SCREENSHOT: filtered C2 traffic view]`

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Command & Control | T1071.001 Application Layer Protocol (Web) |
| Command & Control | T1219 Remote Access Software |
| Exfiltration | T1041 Exfiltration Over C2 Channel |

## Detection signals a SOC would use

- Alert on the `NetSupport Manager` user-agent string — never legitimate browser traffic
- Flag >10 POSTs/hour from one host to the same external IP (beaconing)
- Flag any direct-to-IP outbound HTTP with no preceding DNS lookup

## Tools

Wireshark 4.x, on a locally stored PCAP — no live malicious traffic involved.
