# NexaCorp DFIR: INC-2026-005 - OS Command Injection and Web Shell

OS command injection, web shell deployment, and SSH pivot on a web application portal. Blue Team forensic investigation and Suricata detection engineering.

[![ci](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005/actions/workflows/ci.yml/badge.svg)](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005/actions/workflows/ci.yml)
[![Methodology](https://img.shields.io/badge/methodology-NIST%20SP%20800--61r2-blue.svg)](#methodology)
[![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Detection](https://img.shields.io/badge/Suricata-5%20rules%20validated-green.svg)](detection/local-cmdinjection.rules)
[![CWE](https://img.shields.io/badge/CWE--78-OS%20Command%20Injection-orange.svg)](https://cwe.mitre.org/data/definitions/78.html)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johan--Emmanuel%20Hatchi-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

This repository documents a SOC analyst engagement carried out as part of the BeCode Cybersecurity Bootcamp (promotion 2025-2026). It reconstructs a full intrusion from network and log evidence, then delivers a validated set of network detection rules. It is the fifth incident in the NexaCorp DFIR series.

---

## Operational notice

This is a training engagement against fictitious infrastructure. NexaCorp Industries is a fictional client used as the scenario for the BeCode Brussels bootcamp. The host `bru-web-01` is an isolated lab VM running a deliberately vulnerable web application (DVWA). No production system, customer data, or third party was involved.

All IP addresses, hostnames, and accounts referenced here (`172.16.50.10`, `bru-web-01`, `j.martin`, and similar) are lab-local artifacts, not real-world threat intelligence. Do not feed them to a production SIEM as IOCs.

---

## At a glance

| Field | Value |
|---|---|
| Reference | INC-2026-005 |
| Affected host | bru-web-01 (employee self-service portal) |
| Attacker | 172.16.50.10 (external, curl/8.14.1) |
| Root cause | OS command injection (CWE-78) on an unsanitised diagnostic input |
| Outcome | RCE as www-data, /etc/passwd exfiltration, web shell persistence, SSH pivot |
| Capture window | 5 June 2026, approx 8 hours (08:00 to 15:47, UTC+02:00) |
| Evidence | web_access.log, auth.log, attack.pcap |
| Phases | Phase 1 forensic analysis, Phase 2 Suricata detection |
| Related incident | [INC-2026-004](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004) (SQL injection, same host) |

| Investigation output | Value |
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

## Engagement context

**Scenario (fictional).** NexaCorp Industries reported a security incident on its employee self-service portal `bru-web-01`. The engagement was reported by Marc Wauters (IT Infrastructure Manager) on Monday 8 June 2026, covering an intrusion captured on Friday 5 June 2026.

**Scope.** Phase 1 is a forensic analysis of the evidence bundle (web_access.log, auth.log, attack.pcap). Phase 2 is a Suricata detection-engineering phase: five rules authored and validated against the capture. The attack window investigated runs from the initial login at 08:00 to the SSH pivot at 15:47 (UTC+02:00).

**Educational context.** Delivered during the BeCode Brussels Blue & Red Team bootcamp (November 2025 to September 2026) as Mission 05.

**What is different from previous incidents.** INC-2026-005 is a live-detection engagement, not a forensic-only assessment. Unlike INC-2026-003 (month-1 consolidation, forensic only), it includes a full Phase 2: five Suricata rules authored, validated against the capture in deterministic offline mode (`suricata -r`), with per-rule logic, proof, and false-positive analysis. It is also the second documented incident on the same host as INC-2026-004 (SQL injection); two distinct injection vulnerabilities on one machine within days is itself a finding, and drives the recommendation for a full application code review.

---

## Executive summary

The employee portal `bru-web-01` was breached on 5 June 2026 over a capture window of roughly eight hours (08:00 to 15:47). An external attacker (172.16.50.10) abused the diagnostic "ping a device" feature to run system commands directly on the server: an OS command injection. The attacker confirmed code execution as the web server account (`www-data`), read the contents of `/etc/passwd`, and dropped a web shell that guaranteed repeated access.

A neighbouring feature, the file viewer, was also probed, but every Local File Inclusion attempt failed: the real data leak went through the command injection, not the file viewer. After taking control through the web shell, the attacker logged in over SSH using the valid credentials of an employee (`j.martin`), gaining persistent interactive access. The root cause is an unfiltered input field that passes user input straight to the OS. Five Suricata rules were authored to detect each stage of this attack.

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

## How to read this repository

| If you are a... | Start here | Time |
|---|---|---|
| **Recruiter or hiring manager** | This README + the [report](reports/INC-2026-005_Findings_Report.md) executive summary | 5 min |
| **SOC analyst evaluating fit** | [Report](reports/INC-2026-005_Findings_Report.md) sections 3 (Technical analysis) and 6 (Detection) + [`evidence-summary/ioc-summary.md`](evidence-summary/ioc-summary.md) | 20 min |
| **Detection engineer** | [`detection/local-cmdinjection.rules`](detection/local-cmdinjection.rules) + [`detection/README.md`](detection/README.md) for per-rule logic and offline validation | 30 min |
| **DFIR practitioner** | Full [report](reports/INC-2026-005_Findings_Report.md) + [`methodology/attack-timeline.md`](methodology/attack-timeline.md) + [`notes/journal.md`](notes/journal.md) | 45 min |
| **Anyone who wants to grep, cite, or diff** | [Markdown source of the report](reports/INC-2026-005_Findings_Report.md) | as needed |

---

## Methodology

The engagement follows standard incident-response and detection frameworks:

- **NIST SP 800-61r2** (incident handling) and **NIST SP 800-86** (forensic techniques): structure the Detection & Analysis work.
- **SANS PICERL**: the Identification stage is the core of Phase 1 (log and PCAP correlation, hypothesis-driven reconstruction).
- **MITRE ATT&CK Enterprise v15**: every finding is mapped to one or more techniques (see [`methodology/attck-mapping.md`](methodology/attck-mapping.md)).
- Weakness classification: **CWE-78** (OS command injection), **CWE-22** (path traversal), and **OWASP Top 10 A03:2021** (injection).

**Evidence and timestamps.** All timestamps come from `web_access.log` and `auth.log` (real request time). Wazuh timestamps reflect SIEM indexing time and are not used for the timeline.

**Detection validation.** Rules are validated offline (`suricata -r`), which performs full TCP reassembly without network-timing constraints and yields deterministic counts, unlike live `tcpreplay` on the lab interface. Full detail in [`detection/README.md`](detection/README.md).

---

## Tools used

- **tshark**: PCAP analysis, TCP stream following, and HTTP field extraction (payload reconstruction, response sizing, alert cross-checks).
- **Suricata 6.0.4**: rule validation in offline mode (`-r`) against the capture.
- **tcpreplay / tcprewrite**: live-replay testing and MTU rewrite (`--mtu=1450 --mtu-trunc`) on the lab interface; found non-deterministic for large multi-segment responses, hence the offline reference.
- **grep / sort / uniq**: per-SID alert counting from `fast.log`.

---

## Detection engineering

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

## Repository layout

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

## Reproducibility

The evidence bundle is BeCode lab property and is not redistributed. With your own copy, the detection rules can be revalidated offline:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r attack.pcap -l ~/suri-offline \
  -S /etc/suricata/rules/learner/lab.rules --runmode single
grep -oE '\[1:[0-9]+:[0-9]+\]' ~/suri-offline/fast.log | sort | uniq -c
```

Offline mode (`-r`) is the deterministic reference. Live replay with `tcpreplay` on the lab interface (MTU 1450) loses reassembly of large multi-segment responses and yields unstable counts. Per-rule logic, the offline proof, and the false-positive analysis are in [`detection/README.md`](detection/README.md).

---

## Known limits

- **Live replay is non-deterministic.** On the lab interface (MTU 1450, topspeed), `tcpreplay` loses reassembly of large multi-segment responses; response-side rules fired inconsistently. Offline `suricata -r` is the reliable reference for all counts.
- **Count discrepancy on rule 1000002.** The CTF platform scored web-shell usage at 4; the forensically exact offline count is 2 (the two real shell requests, confirmed with tshark). The difference is attributable to TCP retransmissions in the platform's live replay.
- **Credential source not proven.** The `j.martin` SSH password is not visible in the PCAP. `/etc/passwd` holds only the `x` placeholder (the hash sits in `/etc/shadow`), so the credential was guessed, obtained by means not captured, or already known. The PCAP does not settle which.
- **Broad rule pending tightening.** Rule 1000001 matches `etc` in the request body, which is broad: nil-risk on this capture but to be scoped to a system-path context in production.
- **Evidence bundle not redistributed.** The logs and capture are BeCode lab property; claims are reproducible by anyone holding their own copy.

---

## NexaCorp DFIR series

- [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001): Linux infrastructure compromise (vsftpd backdoor, Caldera C2)
- [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002): privilege escalation and persistence (Tor SSH, SUID, backdoor account)
- [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003): month-1 cross-incident assessment
- [INC-2026-004](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004): SQL injection (same host bru-web-01)
- **INC-2026-005**: this repository
- [INC-2026-006](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-006): stored XSS and session hijacking (web portal)
- [INC-2026-007](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-007): IDOR and broken access control (NexaPortal); Month 2 capstone

---

## Acknowledgments

- **Thomas B.** (BeCode lab coach): scenario design and publication authorization for portfolio use.
- **MITRE** for the ATT&CK knowledge base used to map every finding.
- **Suricata project** for the detection engine used to validate the ruleset.

---

## About

Solo DFIR engagement delivered during the [BeCode Brussels](https://becode.org) Blue & Red Team bootcamp (November 2025 to September 2026), Mission 05.

Author: **[Johan-Emmanuel Hatchi](https://github.com/Jhatchi)** ([LinkedIn](https://www.linkedin.com/in/johan-emmanuel-hatchi/)).

Open to cybersecurity internship opportunities starting September 2026 in Belgium. Looking for SOC / DFIR / detection engineering roles where this kind of end-to-end work (PCAP forensics, log correlation, IDS rule writing, formal client reporting) is in scope.

---

## License

[MIT](LICENSE), 2026 Johan-Emmanuel Hatchi.

The report text and methodology notes are released under MIT: free to copy, adapt, and reuse with attribution. The evidence bundle, lab infrastructure, and original engagement briefings remain BeCode Brussels property and are not redistributed.
