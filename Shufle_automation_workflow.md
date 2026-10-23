## 8. SOAR Automation with Shuffle

Shuffle is the SOAR layer that turns a Wazuh alert into action. Two pipelines were built, each triggered by a Wazuh alert forwarded to a Shuffle webhook. The overall workflow is shown below:

![Shuffle workflow](/images/Shufle_workflow.png)

The design principle is a clean separation: Wazuh decides *what* is suspicious, Shuffle decides *what to do about it*, and a human approves anything destructive. Each node in a pipeline consumes the output of the node before it, so the configuration is as much about wiring data between nodes as about the nodes themselves.

### Shared setup

Two things are configured once and reused by both pipelines.

**1. Wazuh → Shuffle integration (`ossec.conf` on the manager)**

The manager forwards selected alerts to a Shuffle webhook via an `<integration>` block. The integration `name` must be exactly `shuffle` (the module name) — naming it after the use case stops it loading — and the `hook_url` must have no trailing whitespace:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_xxx</hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

`<rule_id>` is the filter that decides which alerts are pushed: only alerts from the listed rules reach this webhook, which keeps each pipeline focused and avoids flooding Shuffle. A second `<integration>` block forwards the brute-force rules (`<rule_id>5710,5712,5763</rule_id>`) to a second webhook. `<alert_format>json</alert_format>` is required so Shuffle receives structured fields it can address individually rather than a flat log string. The manager is restarted after editing.

**2. App authentications in Shuffle**

Each external app needs its credentials configured once (Shuffle stores them as reusable "authentication" objects, so the API keys never appear in the workflow nodes):

- VirusTotal — API key.
- TheHive — base URL (the public ngrok URL of the local TheHive) plus an org API key.
- Wazuh — manager address, API port 55000, and API user/password.
- Email — SMTP server or Shuffle's built-in email app.

### Pipeline A — Mimikatz enrichment and case creation

Trigger: rule 100002 (Mimikatz). Flow: **webhook → extract SHA256 → VirusTotal file report → create TheHive alert → email the analyst.**

**Webhook trigger.** The starting node. Its generated URL is the `hook_url` placed in the Mimikatz `<integration>` block above. When Wazuh posts the alert, the full alert JSON becomes the execution input, referenced downstream as `$exec` (e.g. `$exec.text.win.eventdata.hashes`).

**Regex node — extract the hash.** Sysmon reports hashes as one combined string (e.g. `SHA1=...,MD5=...,SHA256=...`). A Regex **capture group** `SHA256=([A-Fa-f0-9]{64})` is run against `$exec.text.win.eventdata.hashes` to pull out just the SHA256. The capture group (not the full match) is used so the output is a clean 64-character hash with no `SHA256=` prefix — that prefix is what caused earlier "not found" errors at VirusTotal.

**VirusTotal — Get a hash report.** The extracted hash is passed as the `Id` parameter (referencing the Regex node's output). VirusTotal uses the hash as the unique identifier to look up the file (`GET /files/{id}`) and returns its detection ratio and malware classification. No file upload is needed — the hash alone identifies the file.

**TheHive — Create alert.** The enrichment is turned into a case record. This node authenticates with the TheHive URL + API key configured above. The alert body is built from fields of the previous nodes (file name, hash, VirusTotal verdict, host). Two configuration points mattered:

- `sourceRef` must be unique per alert, or TheHive rejects duplicates — a value derived from the Wazuh alert id is used.
- Windows command lines contain backslashes and quotes that break the JSON body ("Invalid json"). Liquid filters escape backslashes first and then double-quotes, in that order, before the value is inserted.

**Email.** The final node notifies the analyst with a summary (host, file, hash, VirusTotal result, and a link to the TheHive case), using the email authentication configured earlier.

### Pipeline B — SSH brute force with human-in-the-loop blocking

Trigger: brute-force rules (5710/5712/5763). Flow: **webhook → enrich source IP → ask the analyst → block on approval.**

**Webhook trigger.** The second hook, wired to the brute-force `<integration>` block. The attacking address arrives as `$exec...data.srcip`.

**VirusTotal — Get an IP report.** `data.srcip` is passed as the `Id`, returning the reputation of the attacking address (malicious-vote count, country, ASN) so the analyst has context before deciding.

**User Input — the human-in-the-loop gate.** This node emails the analyst a block/allow decision and **pauses the workflow** until they respond. It is placed deliberately before any destructive step, so an automated block never happens without human approval. The email includes the source IP and the VirusTotal verdict so the decision is informed.

**Wazuh — Run command (active response).** On approval, this node calls the Wazuh API to run `firewall-drop` on the endpoint, passing the source IP as the argument and the target agent id. Wazuh then adds an iptables DROP for that IP on the agent. If the analyst declines, the branch ends without action.

### Wazuh API authentication (used by Pipeline B)

The Run-command node calls the Wazuh API on port 55000, which requires a short-lived JWT. The token is fetched at run time and expires after 15 minutes, so it is requested fresh each execution rather than stored:

```bash
curl -u <user>:<pass> -k -X GET "https://<public-ip>:55000/security/user/authenticate?raw=true"
```

The returned token is then sent as `Authorization: Bearer <token>` on the active-response call. The Azure NSG was opened on 55000 so cloud Shuffle can reach the API.

### How the nodes pass data to each other

The pipelines work because every node addresses the output of earlier nodes by reference rather than by copying values:

- `$exec.<path>` reaches into the original Wazuh alert JSON (e.g. `$exec...data.srcip`).
- `$<node_name>.<field>` reaches into an earlier node's result (e.g. the Regex node's captured group feeding the VirusTotal `Id`).
- Liquid filters transform a value in place (the backslash-then-quote escaping for TheHive).

This is also where most of the debugging time went: a wrong field path, a non-unique `sourceRef`, or unescaped characters each break silently at the node that consumes them, so each link was validated by inspecting a node's output before wiring the next.

### End-to-end validation

Both pipelines were confirmed end to end: a simulated attack raises the Wazuh alert, the matching `<integration>` forwards it, the case appears in TheHive, the email arrives, and (Pipeline B) the analyst-approved block takes effect on the endpoint.
