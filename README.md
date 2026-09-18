markdown
# Firewall Traffic Control and Forensic Verification

**SBT-DF203 · Lab 6 · Practical validation of a Linux host-based firewall**

Forensic validation of an `iptables` INPUT rule in a two-VM laboratory environment. Correlates packet capture evidence with firewall rule counters and application behaviour to prove policy enforcement and confirm clean restoration.

---

## Document Information

| | |
| :--- | :--- |
| **Student** | Ibrahim Diseh Garba |
| **Registration No.** | `2025/FWSD/11521` |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Institution** | International Cybersecurity and Digital Forensics Academy (ICDFA) |
| **Course** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Instructor** | Aminu Idris, AMCPN |
| **Delivery Block** | 2/3 of 3 |
| **Submission Date** | 18 September 2026 |

---

## Overview

This repository documents the forensic verification of a Linux host-based firewall rule applied in a two-VM laboratory. A narrow INPUT-chain rule was inserted, tested, and removed on the server VM to determine whether HTTP traffic from a designated client could be blocked while other traffic remained unaffected.

The evidence package combines three independent sources:

- **Packet-level:** PCAP captures of the allowed and blocked sessions
- **Rule-level:** `iptables` ruleset snapshots and rule counters
- **Application-level:** `curl` output from the client before, during, and after the block

The rule matched one source IP, the TCP protocol, and destination port 80, with a DROP target. Following the blocked test, the rule was removed using the exact specification and the ruleset was verified byte-identical to the pre-lab snapshot.

The full forensic report, including screenshot references and interpretation, is available as `SBT-DF203-Lab6_2025-FWSD-11521_Ibrahim_Diseh_Garba.pdf`.

---

## Key Findings

| Indicator | Allowed Session | Blocked Session |
| :--- | :---: | :---: |
| Client SYN visible | Yes | Yes |
| Server SYN-ACK visible | Yes | **No** |
| Handshake completed | Yes | **No** |
| HTTP request visible | Yes | **No** |
| HTTP response visible | 200 OK | **No** |
| TCP retransmissions | 0 | **3** |
| iptables counter delta | 0 | **Non-zero** |
| Client `curl` result | `HTTP 200 OK` | `Connection timed out` |

The firewall rule produced a clean, attributable DROP pattern: repeated client SYNs with no reply from the server, a 10-second client timeout, and non-zero rule counters independently confirming the match.

---

## Repository Structure
SBT-DF203-Lab6-2025-FWSD-11521/
├── README.md
├── SBT-DF203-Lab6_2025-FWSD-11521_Ibrahim_Diseh_Garba.pdf
│
├── evidence/
│ ├── http_allowed.pcapng
│ └── http_blocked.pcapng
│
├── working/
│ ├── http_allowed_working.pcapng
│ └── http_blocked_working.pcapng
│
├── reports/
│ ├── iptables_before.rules
│ ├── iptables_before_sha256.txt
│ ├── iptables_after_add.txt
│ ├── iptables_after_test.txt
│ ├── iptables_restored.rules
│ ├── iptables_restored_sha256.txt
│ ├── rule_verification.txt
│ ├── http_allowed_sha256.txt
│ ├── http_blocked_sha256.txt
│ ├── blocked_retransmissions.txt
│ ├── allowed_vs_blocked.tsv
│ ├── server_interfaces.txt
│ ├── server_routes.txt
│ ├── apache_listener.txt
│ └── final_evidence_hashes.txt
│
├── screenshots/
│ ├── fig_1.1_folder_structure.png
│ ├── fig_1.2_server_identity.png
│ ├── fig_1.3_client_identity.png
│ ├── fig_1.4_ufw_disabled.png
│ ├── fig_1.5_client_tools.png
│ ├── fig_1.6_training_page.png
│ ├── fig_1.7_apache_listener.png
│ ├── fig_2.1_ruleset_preserved.png
│ ├── fig_3.1_baseline_curl.png
│ ├── fig_4.1_allowed_capture.png
│ ├── fig_4.2_allowed_hashes.png
│ ├── fig_5.1_rule_inserted.png
│ ├── fig_5.2_rule_verified.png
│ ├── fig_6.1_blocked_curl.png
│ ├── fig_6.2_rule_counters.png
│ ├── fig_6.3_blocked_capture.png
│ ├── fig_7.1_allowed_vs_blocked.png
│ ├── fig_8.1_rule_removed.png
│ ├── fig_8.2_restored_access.png
│ ├── fig_8.3_ruleset_restored.png
│ └── fig_9.1_final_hashes.png
│
└── exported/

text

---

## Evidence Trail

### Baseline — Original Firewall State

The server's firewall ruleset was exported and hashed before any change, establishing the pre-lab chain of custody.


sudo iptables-save | tee reports/iptables_before.rules
sudo iptables -L -n -v --line-numbers | tee reports/iptables_before.txt
sha256sum reports/iptables_before.rules | tee reports/iptables_before_sha256.txt
https://screenshots/fig_2.1_ruleset_preserved.png

Figure 2.1 — Original firewall ruleset exported and hashed.

Allowed Session — Baseline HTTP Capture
A complete HTTP session was captured between the client and the server's Apache listener, confirming baseline connectivity before any rule change.

bash
sudo tshark -i "$SERVER_IFACE" -f "host $CLIENT_IP and tcp port 80" \
  -a duration:30 -w /tmp/http_allowed.pcapng &
https://screenshots/fig_4.1_allowed_capture.png

Figure 4.1 — Allowed session showing complete three-way handshake and HTTP exchange.

Blocking Rule — Insertion and Verification
A narrow DROP rule was inserted at position 1 of the INPUT chain, matching only the client IP on TCP/80.

bash
sudo iptables -I INPUT 1 -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP
sudo iptables -C INPUT -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP
https://screenshots/fig_5.1_rule_inserted.png

Figure 5.1 — DROP rule inserted as rule #1 in the INPUT chain.

Blocked Session — Capture and Counters
The blocked attempt produced a 10-second timeout on the client, three SYN retransmissions in the capture, and non-zero counters on the firewall rule.

https://screenshots/fig_6.2_rule_counters.png

Figure 6.2 — Rule counters incremented, confirming the rule matched the traffic.

https://screenshots/fig_6.3_blocked_capture.png

Figure 6.3 — Repeated SYN retransmissions with no server reply.

Restoration — Rule Removal and Verification
The rule was removed by exact specification, and the restored ruleset was verified byte-identical to the original.

sudo iptables -D INPUT -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP
diff reports/iptables_before.rules reports/iptables_restored.rules
https://screenshots/fig_8.3_ruleset_restored.png

Figure 8.3 — Empty diff between original and restored rulesets.

Reproducing the Lab
Prerequisites
Two Kali Linux VMs on the same isolated network

sudo privileges on both VMs

Apache2 installed on the server VM

Setup
bash
mkdir -p ~/SBT-DF203-Lab6/{evidence,working,reports,screenshots}

# On the server VM
sudo apt update
sudo apt install -y apache2 curl iptables tshark wireshark
sudo systemctl enable --now apache2
sudo ufw disable

# On the client VM
sudo apt update
sudo apt install -y curl tshark wireshark
Preservation and Baseline
bash
# On the server — export and hash the original ruleset
cd ~/SBT-DF203-Lab6
sudo iptables-save | tee reports/iptables_before.rules
sha256sum reports/iptables_before.rules | tee reports/iptables_before_sha256.txt

# On the server — capture allowed session (Terminal 1)
sudo tshark -i eth0 -f "host $CLIENT_IP and tcp port 80" \
  -a duration:30 -w /tmp/http_allowed.pcapng &

# On the client — trigger HTTP (Terminal 2)
curl -v "http://$SERVER_IP/firewall_lab.html"

# On the server — preserve the allowed capture
wait
sudo cp /tmp/http_allowed.pcapng evidence/http_allowed.pcapng
sudo chown ibrahim:ibrahim evidence/http_allowed.pcapng
Insert, Test, and Remove the Rule
bash
# Insert the narrow DROP rule
sudo iptables -I INPUT 1 -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP

# Verify
sudo iptables -C INPUT -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP

# Capture the blocked attempt
sudo tshark -i eth0 -f "host $BLOCKED_CLIENT_IP and tcp port 80" \
  -a duration:35 -w /tmp/http_blocked.pcapng &

# From the client (will time out)
curl -v --connect-timeout 10 "http://$SERVER_IP/firewall_lab.html"

# Preserve the blocked capture and counters
wait
sudo cp /tmp/http_blocked.pcapng evidence/http_blocked.pcapng
sudo chown ibrahim:ibrahim evidence/http_blocked.pcapng
sudo iptables -L INPUT -n -v --line-numbers | tee reports/iptables_after_test.txt

# Remove the rule by exact specification
sudo iptables -D INPUT -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP

---

# Confirm restoration
sudo iptables-save | tee reports/iptables_restored.rules
diff reports/iptables_before.rules reports/iptables_restored.rules \
  && echo 'Ruleset restored — no differences.'
Forensic Interpretation
Why does DROP produce SYN retransmissions and a timeout?
DROP silently discards packets without sending any response. The client's TCP stack follows its standard retransmission policy — typically SYN at ~1s, ~3s, ~7s — and eventually times out. The absence of any reply is itself the evidence: nothing comes back to inform the client that the packet was rejected.

How would REJECT differ?
REJECT sends either an ICMP unreachable or a TCP RST. The client receives an immediate Connection refused error rather than waiting. In a capture, the server's ICMP or RST packet is visible, providing direct diagnostic evidence. The forensic distinction is silence (DROP) versus explicit rejection (REJECT).

Why are firewall counters valuable corroborating evidence?
They independently confirm the rule matched the specific traffic. The PCAP proves the client sent SYNs; the counters prove the server's firewall processed and dropped them. Without counters, an analyst cannot distinguish a lost packet from a firewall-enforced drop.

What distinguishes "server down" from "firewall blocked"?
If the server were down, the host's TCP stack would reply with a TCP RST because no process is listening on port 80. The client would see Connection refused immediately — not a timeout. Also, ss -lntp | grep ':80' on the server would show nothing listening, and firewall counters would remain at zero.

What is the risk of deleting by line number?
Line numbers are positional, not identity-based. Any shift in the rule ordering above the target can cause iptables -D CHAIN <number> to delete the wrong rule. Always delete by exact specification.

---

## Detection and Mitigation
Control	Purpose
Rule counter monitoring	Track packet/byte deltas on key rules; alert on unexpected matches
Centralised logging	Forward iptables LOG targets to a SIEM for correlation
Configuration drift detection	Compare running ruleset against a signed baseline
Default-deny policy	Configure chains with a DROP policy and explicit ACCEPT rules
Narrowly scoped rules	Match by source IP, protocol, and destination port
Change-control process	Document and approve every firewall modification
Safety Statement
This lab was conducted under ICDFA authority in a two-VM environment. The blocking rule was scoped to a single source IP, TCP protocol, and destination port 80, applied only to the INPUT chain of the server VM. The rule was removed within minutes and the ruleset was verified byte-identical to the pre-lab snapshot.

The VMs were on a bridged adapter rather than an isolated host-only switch. To preserve safety controls, the rule could not affect any device other than the designated client VM. No rule matching 0.0.0.0/0, any, or any port other than 80 was ever inserted.

Warning: iptables rules affect live network traffic. Never insert wildcard rules on a system you do not own or a network you are not authorised to modify. Always export and hash the ruleset before any change.

References
ICDFA. (2026). SBT-DF203 — Module 5: Linux Firewall and Packet Drop Forensics — Course Materials.

ICDFA. (2026). SBT-DF203 Lab 6 — Firewall Traffic Control and Forensic Verification — Official Lab Manual.

Netfilter Project. iptables Documentation.

RFC 791. (1981). Internet Protocol.

RFC 793. (1981). Transmission Control Protocol.

Wireshark Foundation. Wireshark User Guide.

---

License
Submitted as academic coursework for SBT-DF203 Lab 6 at the International Cybersecurity and Digital Forensics Academy (ICDFA). Contents may not be redistributed, reused, or reproduced without written permission from the author and ICDFA.

© 2026 Ibrahim Diseh Garba. All rights reserved.
