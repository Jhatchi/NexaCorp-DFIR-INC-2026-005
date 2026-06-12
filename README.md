# NexaCorp DFIR: INC-2026-005

[![ci](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005/actions/workflows/ci.yml/badge.svg)](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005/actions/workflows/ci.yml)
[![Methodology](https://img.shields.io/badge/methodology-NIST%20SP%20800--61r2-blue.svg)](#standards-and-frameworks)
[![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Detection](https://img.shields.io/badge/Suricata-5%20rules%20validated-green.svg)](detection/local-cmdinjection.rules)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johan--Emmanuel%20Hatchi-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

OS command injection, web shell deployment, and SSH pivot on a web application portal. Blue Team forensic investigation and Suricata detection engineering.

This repository documents a SOC analyst engagement carried out as part of the BeCode Cybersecurity Bootcamp (promotion 2025-2026). It reconstructs a full intrusion from network and log evidence, then delivers a validated set of network detection rules. It is the fifth incident in the NexaCorp DFIR series.

> Training engagement on a controlled DVWA-based lab. No production system, customer data, or third party was involved. All IP addresses, hostnames, and accounts belong to the BeCode SOC training environment.

---

## Incident at a glance

| Field | Value |
|---|---|
| Reference | INC-2026-005 |
| Affected host | bru-web-01 (employee self-service portal) |
| Attacker | 172.16.50.10 (external, curl/8.14.1) |
| Root cause | OS command injection (CWE-78) on an unsanitised diagnostic input |
| Outcome | RCE as www-data, /etc/passwd exfiltration, web shell persistence, SSH pivot |
| Capture window | 5 June 2026, approx 10 hours (08:00 to 15:47, UTC+02:00) |
| Evidence | web_access.log, auth.log, attack.pcap |
| Phases | Phase 1 forensic analysis, Phase 2 Suricata detection |
| Related incident | INC-2026-004 (SQL injection, same host) |

---

## Kill chain summary

The attacker moved in deliberate stages over roughly four hours, each building on the last:

1. **Authentication** to the portal (08:00:02).
2. **Command injection** against the "ping a device" diagnostic tool: a benign `ip=127.0.0.1` value followed by injected shell commands after the `;` separator.
3. **Reconnaissance** through the injection: `id`, `whoami`, `cat /etc/passwd`, `ls -la /var/www/html/`, `uname -a`.
4. **Sensitive file read**: the `/etc/passwd` contents leaked in the HTTP response body, exposing all local accounts including root and j.martin.
5. **Web shell deployment**: a command injection POST wrote `/shell.php` to disk, establishing persistence independent of the portal session.
6. **Web shell usage**: GET requests to `/shell.php?cmd=` confirmed repeatable RCE as www-data.
7. **SSH pivot**: three successful SSH logins as j.martin from the attacker IP (15:47), escalating from web-process execution to an interactive foothold.

A parallel set of five Local File Inclusion attempts against the file viewer all failed, each returning an identical 3868-byte default error page. The real data leak came through command injection, not LFI. This distinction is established with response-body evidence in the report.

---

## Key metrics

| Metric | Value |
|---|---|
| Attacker requests | 18 (lowest volume of its subnet, the opposite of noisy scanners) |
| Command injection POSTs | 7 |
| Failed LFI attempts | 4 (plus 1 baseline) |
| Web shell invocations | 2 |
| Successful SSH logins (pivot) | 3 |
| Suricata detection rules authored | 5 (SID 1000001 to 1000005) |
| Rules firing against the capture | 5 of 5 |
| MITRE ATT&CK techniques mapped | 9 across 5 tactics |

---

## What is different from previous incidents

INC-2026-005 is a **live-detection engagement**, not a forensic-only assessment. Unlike INC-2026-003 (month-1 consolidation, forensic only), this incident includes a full Phase 2: five Suricata rules authored, validated against the capture in deterministic offline mode (`suricata -r`), with per-rule logic, proof, and false-positive analysis. The `detection/` directory is the differentiator of this repository.

It is also the second documented incident on the same host as INC-2026-004 (SQL injection). Two distinct injection vulnerabilities on one machine within days is itself a finding, and drives the recommendation for a full application code review.

---

## Repository structure

```
NexaCorp-DFIR-INC-2026-005/
├── README.md                      This file
├── LICENSE
├── .gitignore
├── .markdownlint.json
├── .github/
│   └── workflows/
│       └── ci.yml                 markdownlint + typography validation
├── reports/
│   ├── INC-2026-005_Findings_Report.pdf   Full findings report (23 pages)
│   └── INC-2026-005_Findings_Report.md    Markdown source of the report, readable on GitHub
├── detection/
│   ├── local-cmdinjection.rules   The 5 Suricata rules (SID 1000001-1000005)
│   └── README.md                  Per-rule logic, offline proof, false-positive analysis
├── evidence-summary/
│   └── ioc-summary.md             Indicators of compromise, SIEM-ingestible format
├── methodology/
│   ├── attack-timeline.md         Full request-level timeline
│   └── attck-mapping.md           MITRE ATT&CK mapping table with section references
└── notes/
    └── journal.md                 Investigation journal (post-analysis reconstruction)
```

---

## Detection engineering highlight

Five rules, one per stage of the kill chain, each targeting the Suricata buffer suited to its intent:

| SID | Detects | Buffer | Match |
|---|---|---|---|
| 1000001 | System-file targeting in injection | http.request_body | `etc` in POST body |
| 1000002 | Web shell usage | http.uri | `shell.php` + `cmd=` |
| 1000003 | Web shell write | http.request_body | `shell.php` in POST body |
| 1000004 | RCE confirmed (response side) | file_data | `www-data` in response |
| 1000005 | /etc/passwd exfiltration (response side) | file_data | `root:x:0:0` in response |

The two response-side rules (1000004, 1000005) use the `file_data` buffer to catch successful exploitation, what the server confirms back, rather than only the attacker's request. Counts were validated offline for determinism: live replay on the lab interface (MTU 1450, topspeed) loses reassembly of large multi-segment responses and yields unstable counts. Full detail in `detection/README.md`.

---

## NexaCorp DFIR series

- [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001): Linux infrastructure compromise (vsftpd backdoor, Caldera C2)
- [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002): privilege escalation and persistence (Tor SSH, SUID, backdoor account)
- [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003): month-1 cross-incident assessment
- INC-2026-004: SQL injection (same host bru-web-01)
- **INC-2026-005**: this repository

---

## Standards and frameworks

NIST SP 800-61r2 (incident handling), NIST SP 800-86 (forensic techniques), SANS PICERL, MITRE ATT&CK Enterprise v15, CWE-78 (OS command injection), CWE-22 (path traversal), OWASP Top 10 A03:2021 (injection).

---

*Author: Johan-Emmanuel Hatchi · BeCode Cybersecurity Bootcamp 2025-2026 · [linkedin.com/in/johan-emmanuel-hatchi](https://linkedin.com/in/johan-emmanuel-hatchi)*
