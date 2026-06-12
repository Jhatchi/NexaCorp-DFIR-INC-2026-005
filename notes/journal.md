# Investigation Journal: INC-2026-005

**Honesty note:** this journal is a post-analysis reconstruction, not a real-time logbook. It restructures and narrates the investigation as it was actually carried out, based on the evidence and the commands run. No detail is fabricated; where the evidence did not support a conclusion, that is stated.

---

## Starting point

The engagement opened with the evidence bundle for INC-2026-005: a network capture (attack.pcap, 37 MB), three logs (web_access.log, auth.log, wazuh-alerts.json), and a README. The brief framed a 10-hour monitoring window on the employee portal bru-web-01, with legitimate employee traffic, scanner noise, and one real attack interleaved. The README was explicit that the attacker (172.16.50.10) deliberately shares the scanner subnet, so source IP alone would not isolate it.

The brief also flagged the key trap up front: POST command-injection payloads are not visible in the access log (they sit in the body), while LFI payloads are visible in the URL. That shaped the approach: the access log gives the request-level skeleton, but the PCAP is needed for payload-level truth.

## Phase 1: identification

I started with the access log, as recommended. A per-IP request count confirmed the attacker hides in volume: 172.16.50.10 issued only 18 requests, fewer than several scanners. Filtering that IP's requests revealed the shape of the intrusion immediately: 7 POSTs to the command injection endpoint, 5 GETs to the file viewer, 2 GETs to a `/shell.php` that does not exist in stock DVWA, plus the portal logins.

The auth log gave the pivot: three Accepted SSH logins as j.martin from the attacker IP at 15:47.

To recover the actual injected commands, I followed the seven POST streams in the PCAP. Each carried `ip=127.0.0.1` followed by a shell command after the `;` separator: id, whoami, cat /etc/passwd, ls -la /var/www/html/, uname -a, and finally the echo that writes shell.php. The `cat /etc/passwd` response stream contained the full accounts file in cleartext, including the root line and j.martin. The shell-usage stream (3066) returned `uid=33(www-data)`, confirming the execution context.

## The LFI verdict

The five file-viewer GETs looked alarming on paper: /etc/passwd, /etc/os-release, the DVWA config, an Apache log. But the response sizes told the real story. The baseline (include.php) returned 5510 bytes; all four traversal attempts returned exactly 3868 bytes, identical to each other. That uniform error-page size is the proof that the LFI failed: the viewer served its default page every time, never the requested file. The conclusion that mattered: the data leak came through command injection, not LFI. Reading the access log alone would have misattributed the leak.

## Phase 2: detection engineering

The second phase was authoring Suricata rules, one per stage. The request-side rules came together quickly. The response-side rules did not, and that became the main engineering effort of the session.

The infrastructure fought back first. tcpreplay failed with "Message too long" because the lab interface MTU is 1450 and the capture contained larger frames. The fix was to rewrite the capture to fit: `tcprewrite --mtu=1450 --mtu-trunc`. After that, request-side rules fired reliably under live replay, but the response-side rules were erratic, firing on some runs and not others.

I worked the problem methodically: tried file_data, http.response_body, raw TCP content matches, varied replay speeds from topspeed down to 2000 pps. The request-side rules stayed stable throughout; the response-side rules stayed unstable. The root cause was reassembly: the /etc/passwd leak sits roughly 5 KB deep in a multi-segment response, and live topspeed replay on this VM did not reliably reassemble that segment. The small 54-byte shell response reassembled fine, which is why the RCE rule sometimes fired and the exfiltration rule did not.

The resolution was to stop fighting live replay and read the capture offline with `suricata -r`, which performs full deterministic TCP reassembly with no network-timing constraint. Offline, all five rules fired cleanly and the counts were stable.

## A note on counts

The detection platform scored the rules against its own live replay, and its counts did not always match the deterministic offline counts. The web-shell-usage rule is the clearest case: offline gives 2 (the two real shell requests, confirmed with tshark), while the platform validated 4, attributable to TCP retransmissions in its replay. For the report I used the offline counts as the forensic reference and documented the discrepancy rather than hiding it.

## Lessons learned

- Response size is a first-class forensic signal. The uniform 3868-byte LFI responses settled the leak-channel question before any packet was opened.
- Request-side and response-side detection behave very differently under replay. Response-side rules depend on reassembly that live replay can break; offline mode is the reliable reference for deterministic counts.
- Document discrepancies, do not paper over them. The platform-versus-offline count gap is itself a finding about replay methodology, and stating it is more credible than forcing a single number.
- The same host carried a separate injection flaw the week before (INC-2026-004, SQLi). Two injection vulnerabilities on one machine in days points past spot fixes toward an application code review.
