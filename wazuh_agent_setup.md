# Wazuh Agent — Endpoint Setup

Each monitored host runs a Wazuh agent that registers to the manager and ships telemetry to it on port 1514 (enrollment on 1515). Replace `x.x.x.x` with the manager's IP and `xxx` with a name for the agent.

## Windows agent

Download and install the agent MSI, pointing it at the manager at install time, then start the service:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile $env:TEMP\wazuh-agent.msi
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER='x.x.x.x' WAZUH_AGENT_NAME='xxx' WAZUH_REGISTRATION_SERVER='x.x.x.x'
NET START WazuhSvc
```

- `WAZUH_MANAGER` — where the agent sends events.
- `WAZUH_REGISTRATION_SERVER` — where it enrolls (the same host here).
- `WAZUH_AGENT_NAME` — the name that appears in the dashboard.
- `NET START WazuhSvc` starts the agent service immediately (it is also set to start on boot).

> In PowerShell the temp-directory variable is `$env:TEMP`, not `${env.tmp}`.

### Windows telemetry (Sysmon)

By default the agent forwards Windows Event Logs, but rich process and network detail needs **Sysmon**. After installing Sysmon with a configuration, add a `windows_eventchannel` block to `C:\Program Files (x86)\ossec-agent\ossec.conf` so the Sysmon/Operational channel is forwarded to the manager. This is what provides Event ID 1 (process creation) and Event ID 11 (file creation) — the telemetry the custom detection rules depend on. Restart the agent service after editing.

![Windows telemetry — Sysmon channel](/images/Window_telemetry_sysmon.png)

## Linux agent

Install the agent package with the manager address and name set inline, then enable and start the service:

```bash
curl -o wazuh-agent-4.7.5-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.5-1.x86_64.rpm
sudo WAZUH_MANAGER='x.x.x.x' WAZUH_AGENT_NAME='xxx' rpm -ihv wazuh-agent-4.7.5-1.x86_64.rpm
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

(For Debian/Ubuntu endpoints use the `.deb` package and `dpkg -i` instead of the `.rpm`.)

## Verify enrollment

On the manager, every agent should show **Active**:

```bash
sudo /var/ossec/bin/agent_control -l
```

If an agent shows **Never connected**, the usual causes are a wrong manager IP in the agent config, or the firewall/NSG not allowing ports 1514–1515 from the agent's network.
