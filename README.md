# SOC Automation Lab

An end-to-end Security Operations Center built from open-source tooling, integrating **Wazuh** (SIEM/XDR), **Shuffle** (SOAR), **TheHive** (case management) and **VirusTotal** (threat intel). An alert raised on a monitored endpoint is detected, enriched, recorded as a case, sent to an analyst, and — on approval — answered with an automated firewall block on the attacking host.

The project is built to demonstrate blue-team and detection-engineering skills across the full alert lifecycle: detection, enrichment, incident response, and automated response with a human-in-the-loop approval gate.

## Architecture

The lab deliberately spans a public cloud and a private network, which is where most of the integration work lives: Wazuh and Shuffle are reachable on the public internet, while TheHive and the endpoints sit behind NAT.

| Host | Role | Location |
| --- | --- | --- |
| Wazuh manager | SIEM/XDR, rules engine, indexer, dashboard | Azure VM (public IP) |
| Windows 11 | Monitored endpoint (Wazuh agent + Sysmon) | Local VMware |
| Linux endpoint | Monitored endpoint, SSH brute-force target | On-prem / lab network |
| Shuffle | SOAR orchestration (two pipelines) | Cloud (shuffler.io) |
| TheHive | Case management | Local VM, exposed via ngrok |
| VirusTotal | IP and file-hash enrichment | SaaS |

**Data flow:** endpoint telemetry → Wazuh agent → manager (decoders + rules) → alert → Shuffle webhook → VirusTotal enrichment → TheHive case + analyst email → (on approval) Wazuh active response blocks the source IP.

![Shuffle workflow](/images/Shufle_workflow.png)

## Repository contents

| Document | What it covers |
| --- | --- |
| [Wazuh-Install-Instructions.md](Wazuh-Install-Instructions.md) | Installing the Wazuh all-in-one stack and initial configuration |
| [wazuh_agent_setup.md](wazuh_agent_setup.md) | Enrolling Windows and Linux agents, plus Sysmon telemetry |
| [TheHive-Install-Instructions.md](TheHive-Install-Instructions.md) | TheHive 5 with Cassandra/Elasticsearch, tuning, and the ngrok bridge |
| [Rule_creation.md](Rule_creation.md) | Custom detection rules, active response, testing and lessons learned |
| [Shufle_automation_workflow.md](Shufle_automation_workflow.md) | The two Shuffle SOAR pipelines and how each node is wired |

## What was built

- A multi-component SOC stack integrated across cloud and on-premises hosts.
- Custom Wazuh detection rules (IDs 100000+) for Mimikatz, network scanning/recon, WMI abuse and suspicious downloads, each mapped to MITRE ATT&CK and validated against a live attack.
- Two Shuffle pipelines: Mimikatz enrichment → TheHive case → analyst email; and SSH brute force → VirusTotal → analyst approval → automated `firewall-drop`.
- Active response gated behind human approval, with a trusted-source whitelist and finite block timeout.

## Build order

1. Deploy the Wazuh server (Azure VM).
2. Enroll the endpoints as agents and enable Sysmon telemetry.
3. Deploy TheHive and expose it to cloud Shuffle via ngrok.
4. Write and validate the custom detection rules.
5. Build the Shuffle SOAR pipelines and wire in VirusTotal, TheHive and active response.

## Testing reference

Detections were validated by simulating the attacks they target, including `nmap -sS` (scanning), `hydra` (SSH brute force), `Invoke-WmiMethod` (WMI execution), and LOLBin downloads. Credential-dumping detection was exercised with Mimikatz:
https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919

> Mimikatz is a well-known offensive security tool; it is used here only against isolated lab endpoints to test detection and response.

## Author

Vũ Đức Quân — MSc Cyber Security, University of Southampton.
