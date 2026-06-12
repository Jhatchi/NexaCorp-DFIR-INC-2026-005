# MITRE ATT&CK Mapping: INC-2026-005

Each finding is mapped to MITRE ATT&CK Enterprise techniques (v15). Findings F1 to F4 correspond to the sections of the findings report. The mapping aligns this engagement with industry-standard threat intelligence and enables downstream SIEM detection and threat hunting.

---

## Findings reference

| Ref | Finding | Report section | Severity |
|---|---|---|---|
| F1 | OS command injection on the ping tool: RCE as www-data, /etc/passwd exfiltration | 3.3 | CRITICAL |
| F2 | Web shell /shell.php dropped for repeatable execution (persistence) | 4.1 | HIGH |
| F3 | Local File Inclusion attempts on the file viewer (all failed, no data exposed) | 3.4 | MEDIUM |
| F4 | Valid SSH access as j.martin from the attacker IP (persistent foothold) | 4.2 | CRITICAL |

---

## Technique mapping

| Finding | Tactic | Technique ID | Technique |
|---|---|---|---|
| F1 | Initial Access | T1190 | Exploit Public-Facing Application |
| F1 | Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| F1 | Discovery | T1087.001 | Account Discovery: Local Account |
| F1 | Collection | T1005 | Data from Local System |
| F1 | Discovery | T1082 | System Information Discovery |
| F1 | Discovery | T1083 | File and Directory Discovery |
| F2 | Persistence | T1505.003 | Server Software Component: Web Shell |
| F3 | Initial Access | T1190 | Exploit Public-Facing Application (failed LFI attempt) |
| F4 | Persistence | T1078.003 | Valid Accounts: Local Accounts |
| F4 | Lateral Movement | T1021.004 | Remote Services: SSH |

All technique identifiers are verifiable on attack.mitre.org. None inferred beyond what the evidence supports.

---

## Severity derivation

This is a forensic engagement; no CVSS base score was computed. Each finding's severity is derived from two anchored factors: the demonstrated operational impact in the evidence, and the MITRE ATT&CK technique category of the activity. This is the same method used across the INC-2026 series for comparability between incidents.

- **F1 CRITICAL**: confirmed RCE (response stream 3066, `uid=33(www-data)`) and real data exfiltration (stream 2251, /etc/passwd in the response). Root cause of the entire chain.
- **F2 HIGH**: a repeatable RCE backdoor, but a direct consequence of F1, limited to the www-data context, and trivially remediated (file removal plus web-root scan). Rated High rather than Critical to avoid severity inflation.
- **F3 MEDIUM**: a genuinely vulnerable surface (unsanitised input per section 3.1) that was probed, but four traversals failed with identical 3868-byte responses and zero data exposed.
- **F4 CRITICAL**: a valid credential held, granting a persistent interactive foothold independent of the web shell. The most consequential outcome of the chain.

Distribution: 2 Critical, 1 High, 1 Medium.
