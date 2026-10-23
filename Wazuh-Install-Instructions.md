# Wazuh Server — Installation & Initial Configuration

This guide installs the Wazuh all-in-one stack (manager, indexer, and dashboard on a single host) and prepares it for agent enrollment and API access. The server was deployed on an Azure VM so it has a stable public IP that remote agents and cloud Shuffle can reach.

## Specifications

- RAM: 8 GB minimum
- Disk: 50 GB minimum (SSD recommended — the indexer is I/O-bound)
- OS: Ubuntu 22.04 LTS

## 1. Install Wazuh 4.7 (all-in-one)

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

- `-a` installs **all** components — the manager, the Wazuh indexer (OpenSearch), and the dashboard — on this one host.
- If the installer refuses to run because it does not recognise the OS version or hardware, add `-i` to skip the pre-flight check: `sudo bash ./wazuh-install.sh -a -i`.
- If an `apt`/`dpkg` lock error appears ("An external process is using APT"), wait for the background unattended-upgrade to finish, or clear the lock, then re-run.

## 2. Extract the generated credentials

The installer creates all passwords and certificates inside an archive. Unpack it and read the admin password:

```bash
sudo tar -xvf wazuh-install-files.tar
cat wazuh-install-files/wazuh-passwords.txt
```

The `admin` user's password logs you into the dashboard. The API users (`wazuh` / `wazuh-wui`, also listed here) are what the Wazuh API, and later Shuffle, authenticate with.

## 3. Access the dashboard

Open `https://<server-ip>` in a browser and log in as `admin` with the password from step 2. The certificate is self-signed, so the browser warns on first visit.

> **Network note:** the host firewall / cloud security group must allow inbound **443** (dashboard), **1514/1515** (agent events and enrollment), and **55000** (API) from the networks that need them. On Azure this is the NSG; opening only port 22 (the default) is why the dashboard is unreachable at first.

## 4. Edit the manager configuration

Most customisation — agent settings, integrations (Shuffle), and active response — lives in the manager config. Edit it, then restart the manager to apply the changes:

```bash
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

![Wazuh dashboard settings](/images/wazuh_dashboard_settings.png)

> On an SSH-key Azure VM, `sudo` is passwordless; a `sudo` command that suddenly prompts for a password usually means it was run without `sudo`.

## 5. Verify

- `sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard` — all three should report `active (running)`.
- The dashboard **Agents** page should load (it stays empty until the first agent enrolls).
