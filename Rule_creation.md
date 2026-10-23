## 7. Detection Engineering — Custom Rules

This is the core blue-team work: writing custom detections for behaviours the shipped ruleset misses, and validating that each one fires on a real attack and not on noise. All custom rules live in `/var/ossec/etc/rules/local_rules.xml` on the manager, use IDs from 100000 up, and were validated with `wazuh-logtest` and `wazuh-analysisd -t` before testing against a live attack.

**Method**

- Survey the built-in ruleset first. Several behaviours are already decoded by Wazuh at level 0 (silent), so a naive new rule never fires — the event is consumed by the built-in rule before reaching it. The fix is to **chain** the custom rule to the built-in with `if_sid`, making it a child that raises the level.
- Use the exact Wazuh field names. A field-name error (e.g. `same_source_ip` instead of the correct `same_srcip`) silently prevents correlation; `wazuh-logtest` is the way to confirm the fields actually populate.
- Map each rule to MITRE ATT&CK so alerts carry technique context.

**Rule set 1 — Mimikatz credential dumping (ID 100002, T1003)**

This rule detects Mimikatz usage by Sysmon original-file-name (`mimikatz.exe`) at level 15, and is the trigger for the first SOAR pipeline. Matching on `originalFileName` rather than the on-disk name means a renamed binary (`m.exe`, `x.exe`) is still caught, because the original name is embedded in the PE metadata.

```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
  <description>Mimikatz Usage Detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

**Rule set 2 — Network scan / recon (IDs 100003–100006, T1046)**

Wazuh has no native packet visibility, so a new log source was needed: **iptables logging** on the Linux endpoint. Dedicated LOG rules tag SYN packets and ICMP probes with a prefix, and those log lines are forwarded to Wazuh:

```bash
sudo iptables -I INPUT -p tcp --syn -j LOG --log-prefix "SYN-SCAN: "
sudo iptables -I INPUT -p icmp -j LOG --log-prefix "ICMP-PROBE: "
```

A `localfile` block ships `/var/log/messages` (RHEL) to the manager. The detection is then frequency-based: a low-level base rule matches one packet silently (`no_log`, so it raises no alert of its own and only feeds the counter), and a frequency child fires when many packets arrive from one source in a short window — to many destination ports (a port scan) or many destination IPs (a host sweep):

```xml
<group name="network_scan,recon,">

  <!-- Base: individual SYN packet -->
  <rule id="100003" level="1">
    <if_sid>4100</if_sid>
    <match>SYN-SCAN:</match>
    <description>Firewall: single SYN packet logged</description>
    <options>no_log</options>
  </rule>

  <!-- SYN/port scan: 15 SYN packets to different ports within 10s from same source -->
  <rule id="100004" level="10" frequency="15" timeframe="10">
    <if_matched_sid>100003</if_matched_sid>
    <same_srcip />
    <different_dstport />
    <description>Possible SYN/port scan from source $(srcip)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>recon,attack,network_scan,</group>
  </rule>

  <!-- Base: individual ICMP probe -->
  <rule id="100005" level="1">
    <if_sid>4100</if_sid>
    <match>ICMP-PROBE:</match>
    <description>Firewall: single ICMP packet logged</description>
    <options>no_log</options>
  </rule>

  <!-- ICMP sweep: probes to different destination hosts -->
  <rule id="100006" level="10" frequency="8" timeframe="10">
    <if_matched_sid>100005</if_matched_sid>
    <same_srcip />
    <different_dstip />
    <description>Possible ICMP host sweep from source $(srcip)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>recon,attack,network_scan,</group>
  </rule>

</group>
```

The `same_srcip` / `different_dstport` / `different_dstip` fields are what distinguish a scan (one source hitting many targets fast) from normal traffic. A single SYN or ICMP packet is ordinary, so the alert is deliberately tied to volume from one source, not to any individual packet.

**Rule set 3 — WMI abuse (IDs 100007–100008, T1047)**

Remote execution via WMI shows up in Sysmon Event ID 1 as a process whose **parent** is `WmiPrvSE.exe`. The event was being swallowed by a built-in level-0 rule, so the custom rules are chained to the built-ins that already decode it (`92068` / `92069` / `92070`) and raised to level 12:

```xml
<group name="wmi_abuse,">

  <!-- wmic.exe used to create a process or execute on a remote node -->
  <rule id="100007" level="12">
    <if_sid>92068</if_sid>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)wmic\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)process\s+call\s+create|/node:</field>
    <description>WMI Abuse: wmic.exe usage in host $(win.system.computer) by $(win.eventdata.user): $(win.eventdata.commandLine)</description>
    <mitre>
      <id>T1047</id>
    </mitre>
  </rule>

  <!-- WmiPrvSE.exe spawning a command interpreter (remote WMI execution) -->
  <rule id="100008" level="12">
    <if_sid>92069, 92070</if_sid>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)wmiprvse\.exe$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)\.exe$</field>
    <description>WMI abuse: WmiPrvSE.exe spawned $(win.eventdata.image) in host $(win.system.computer) - possible WMI execution</description>
    <mitre>
      <id>T1047</id>
    </mitre>
  </rule>

</group>
```

Rule 100007 catches direct `wmic.exe process call create` / `/node:` usage; rule 100008 catches the downstream sign of remote execution — a command interpreter whose parent is `WmiPrvSE.exe`.

**Rule set 4 — Suspicious download (IDs 100009–100011, T1105)**

The built-in rules cover some LOLBin downloads (`92074` for curl/wget fetching a PE, `92075` for `certutil -urlcache` fetching a PE), but leave gaps: PowerShell download cmdlets, `bitsadmin /transfer`, and non-PE payload extensions. Three rules close those gaps, all children of `sysmon_event1`:

```xml
<group name="suspicious_download,">

  <!-- PowerShell downloading remote content (gap: no built-in rule) -->
  <rule id="100009" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)(powershell|pwsh)\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(Invoke-WebRequest|\biwr\b|DownloadFile|DownloadString|DownloadData|Start-BitsTransfer|Net\.WebClient)</field>
    <description>Suspicious download: PowerShell downloading remote content on $(win.system.computer)</description>
    <mitre>
      <id>T1105</id>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- bitsadmin transferring a file (gap) -->
  <rule id="100010" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)bitsadmin\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/transfer|/addfile</field>
    <description>Suspicious download: bitsadmin transferring remote file on $(win.system.computer)</description>
    <mitre>
      <id>T1105</id>
      <id>T1197</id>
    </mitre>
  </rule>

  <!-- certutil/curl/wget fetching a NON-PE file (.exe/.dll already handled by 92074/92075) -->
  <rule id="100011" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)(certutil|curl|wget)\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-urlcache|-o |-out|-outfile).+(\.ps1|\.bat|\.scr|\.vbs|\.zip|\.dat|\.txt)</field>
    <description>Suspicious download: $(win.eventdata.originalFileName) fetching non-PE file (possible evasion) on $(win.system.computer)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>

</group>
```

**Validation workflow for every rule**

1. `wazuh-logtest` with a sample event to confirm the decoder fields and that the rule matches.
2. `wazuh-analysisd -t` to confirm the ruleset compiles.
3. Run the real attack and confirm the alert appears on the dashboard at the expected level.

## 9. Active Response — Automated Blocking

Active response is the automated containment step: Wazuh runs the `firewall-drop` script on the endpoint to add an iptables DROP for the attacking source IP. In this lab it is deliberately gated behind the analyst approval from Pipeline B, so the irreversible action never happens without a human decision.

**Manager configuration (`ossec.conf`)**

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <timeout>600</timeout>
</active-response>
```

**What happens on the endpoint**

The script adds a DROP rule for the source IP. On a host that routes traffic the rule can land in the `FORWARD` chain as well as `INPUT`, so both are checked when verifying or clearing a block:

```bash
sudo iptables -L FORWARD -n --line-numbers
sudo iptables -D FORWARD -s <ip> -j DROP
```

**Two lessons that shaped the final config**

- **Whitelist trusted addresses.** During testing the active response blocked my own university VPN address, cutting my access to the endpoint. The fix is a `<white_list>` entry for trusted ranges so the response never blocks administrative sources. (A typo also mattered here: the chain is `FORWARD`, not `FOWARD` — a mistyped delete command silently does nothing and the block appears stuck.)
- **Use a finite timeout in a lab.** `<timeout>600</timeout>` auto-removes the block after ten minutes, which is far easier to recover from than a permanent (`no`) block that must be cleared by hand.

**"AR command was not sent to some agents"**

This warning means the command or agent binding is off — the active-response command must be defined on the manager and the target agent must be connected and support the script. Confirming the agent was Active and the command name matched resolved it.

## 10. Testing, Challenges & Lessons Learned

Every detection was validated by running the attack it is meant to catch — a purple-team loop where a failed detection sent me back to fix the rule or the telemetry.

**Attack simulations and the rules they exercise**

| Technique | Tool / command | Rule(s) |
| --- | --- | --- |
| Credential dumping | Mimikatz executable | 100002 |
| SSH brute force | `hydra -l admin -P wordlist ssh://10.7.5.52` | 5712/5763 + Pipeline B |
| Port scan | `nmap -sS` against the endpoint | 100004 |
| Host sweep | ICMP ping sweep | 100006 |
| WMI abuse | `Invoke-WmiMethod -Class Win32_Process -Name Create` | 100008 |
| Suspicious download | PowerShell `Invoke-WebRequest`, `certutil`, `bitsadmin` | 100009–100011 |

**Challenges and lessons learned**

- **Cloud/on-prem split.** Wazuh and Shuffle are public; TheHive and the endpoints are private behind NAT. Cloud Shuffle cannot reach a private `192.168.x.x` service, which is why TheHive is exposed through an ngrok tunnel. This is the single biggest piece of integration work in the lab.
- **Built-in rules swallow events.** WMI and download events were decoded by built-in level-0 rules before the custom rules saw them. Chaining with `if_sid` (making the custom rule a child of the built-in) is the correct pattern, not writing a competing top-level rule.
- **Use Wazuh's own field names.** An early scan rule used `same_source_ip`; the correct field is `same_srcip`. The wrong name fails silently, so `wazuh-logtest` is essential to confirm fields actually populate.
- **Agent event-queue overflow.** An aggressive `nmap -p- -T4` generated more events than the agent could ship, triggering "agent event queue is full" (rule 203) and dropping the very events the scan rule needed. A moderate `nmap -sS` stays within throughput and fires the rule reliably.
- **Endpoint defences interfere with tests.** Windows Defender / ASR blocked a `certutil` LOLBin download during testing ("Access is denied"); testing from `%TEMP%` or temporarily relaxing real-time protection was needed to exercise the rule.
- **JSON escaping for Windows data.** Backslashes and quotes in Windows command lines break a JSON body sent to TheHive; escape backslashes first, then quotes.
- **Short-lived API tokens.** The Wazuh API JWT expires after 15 minutes, so it is fetched at run time in the pipeline rather than stored.
- **Don't block yourself.** Active response blocked my own VPN address once; a whitelist of trusted ranges and a finite timeout prevent that from locking me out.
- **VMware NAT quirks.** A stuck NAT service blocked TCP/UDP while ICMP still worked; a host reboot cleared it, after much wasted time reconfiguring the guest.
