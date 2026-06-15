# Detection Notes: INC-2026-005

Suricata detection engineering for the OS command injection and web shell intrusion on bru-web-01. Five rules, one per distinct stage of the kill chain, validated against the evidence capture in deterministic offline mode.

---

## Design principle

Each rule targets the Suricata buffer suited to its detection intent:

- **http.request_body** (raw, URL-encoded) for request-side injection payloads. The body is where the command injection lives; it is never in the URL for a POST.
- **http.uri** (normalised) for web shell usage, where the filename and parameter sit in the request line.
- **file_data** (response body) for response-side detection. These rules prove that exploitation *succeeded*, by inspecting what the server sent back, not merely what the attacker sent in.

---

## The five rules

```
alert http any any -> any any (msg:"LAB05 sensitive file targeting in command injection body"; flow:established,to_server; http.request_body; content:"etc"; nocase; sid:1000001; rev:4;)
alert http any any -> any any (msg:"LAB05 web shell usage cmd param"; flow:established,to_server; http.uri; content:"shell.php"; nocase; content:"cmd="; nocase; sid:1000002; rev:1;)
alert http any any -> any any (msg:"LAB05 web shell write via command injection"; flow:established,to_server; http.request_body; content:"shell.php"; nocase; sid:1000003; rev:1;)
alert http any any -> any any (msg:"LAB05 RCE confirmed www-data in response"; flow:established,to_client; file_data; content:"uid="; content:"www-data"; distance:0; sid:1000004; rev:7;)
alert http any any -> any any (msg:"LAB05 data exfil etc-passwd content in response"; flow:established,to_client; file_data; content:"root:x:0:0"; sid:1000005; rev:6;)
```

---

## Per-rule logic

| SID | Stage detected | Buffer | Match | Alerts (offline) |
|---|---|---|---|---|
| 1000001 | System-file targeting in injection | http.request_body | `etc` in POST body | 1 |
| 1000002 | Web shell usage | http.uri | `shell.php` + `cmd=` | 2 |
| 1000003 | Web shell write | http.request_body | `shell.php` in POST body | 1 |
| 1000004 | RCE confirmed (response side) | file_data | `www-data` in response | 6 |
| 1000005 | /etc/passwd exfiltration (response side) | file_data | `root:x:0:0` in response | 1 |

**1000001**: only the `;cat /etc/passwd` payload carries the substring `etc` in its body. The `;ls /var/www/html/` payload contains `var`, not `etc`, so it does not match. One alert.

**1000002**: two GET requests to `shell.php` carry `cmd=` (`?cmd=id` and `?cmd=ls`), the only requests to the shell in the entire capture. One alert per invocation.

**1000003**: a single POST body contains `echo ... > /var/www/html/shell.php`, the deployment event. One alert.

**1000004**: six server responses contain the `www-data` process-identity string (command outputs and DVWA context pages). The narrow variant shown above (`uid=` plus `www-data`) restricts to strict execution proof and yields 2; the deployed rule uses the broad `www-data` match and yields 6.

**1000005**: one server response contains the root line of `/etc/passwd`, the single point where the accounts file leaked into a web response.

---

## Proof (offline replay)

```
=== BY SID ===
      1 [1:1000001:4]
      2 [1:1000002:1]
      1 [1:1000003:1]
      6 [1:1000004:7]
      1 [1:1000005:6]
```

All five rules fire. The offline count is deterministic: Suricata reads the PCAP with `-r` and performs full TCP reassembly without network-timing constraints.

**Validation workflow:**
```
sudo suricata -c /etc/suricata/suricata.yaml -r attack.pcap -l ~/suri-offline \
  -S /etc/suricata/rules/learner/lab.rules --runmode single
grep -oE '\[1:[0-9]+:[0-9]+\]' ~/suri-offline/fast.log | sort | uniq -c
```

---

## Note on live replay versus offline

Live replay with tcpreplay on the lab interface was non-deterministic. The interface MTU is 1450, and topspeed replay of the 64591-packet capture loses reassembly of large multi-segment server responses. Request-side rules (1000001, 1000003) fired consistently; response-side rules (1000004, 1000005) and the usage rule (1000002) varied between runs. The PCAP was first rewritten to fit the MTU:

```
tcprewrite --mtu=1450 --mtu-trunc --infile=attack.pcap --outfile=/tmp/attack_005_mtu1450.pcap
```

Even after the MTU fix, large responses did not reassemble reliably in live topspeed. Offline mode (`-r`) is the robust, deterministic answer and the reference used for all counts in this report.

**Count discrepancy on 1000002**: the CTF scoring platform validated the web-shell-usage flag at 4, while the forensically exact offline count is 2 (the two real shell requests, confirmed independently with tshark). The discrepancy is attributable to TCP retransmissions during the platform's live replay. The forensic figure is 2.

---

## False-positive analysis

| SID | FP risk | Production mitigation |
|---|---|---|
| 1000001 | `content:"etc"` is broad: a legitimate POST body containing the word "etc" would fire. Nil on this capture (no normal portal traffic contains it), but it should be tightened in production. | Replace with `%2Fetc%2F`, or require path context (the `;` separator plus `/etc/`) so it matches only an injected system path. |
| 1000002 | Low. `shell.php` plus `cmd=` in the URI is highly specific to a web shell. | Restrict to GET and the exact path `/shell.php` once the web root is known. |
| 1000003 | Low. `shell.php` in a POST body is anomalous. | Combine with the injection separator (`%3B`) to reduce further. |
| 1000004 | `content:"www-data"` matches any response containing that string, including DVWA context pages. Six responses match on this capture. In production, legitimate content could mention www-data. | Combine with `content:"uid="` to match only strict execution proof, bringing the count to the 2 responses containing `uid=33(www-data)`. A sensitivity versus specificity trade-off. |
| 1000005 | Very low. `root:x:0:0` in an HTTP response means an /etc/passwd file leaked: no legitimate web response contains it. | None needed; usable as-is. |

---

## Environment notes

- Suricata 6.0.4 RELEASE, running offline (`-r`) for validation.
- suricata.yaml response inspection: response-body-limit 100kb, inspect-window 16kb, minimal-inspect-size 40kb. Adequate; not the limiting factor for the response-side rules.
- The active ruleset file is `/etc/suricata/rules/learner/lab.rules`.
