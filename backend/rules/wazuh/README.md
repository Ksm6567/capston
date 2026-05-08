# Wazuh Rules

This project now treats the official Wazuh ruleset as the primary detection source. Wazuh detection should run inside a real Wazuh manager using its default ruleset, and this app should consume the manager's generated alerts.

The official ruleset is installed with Wazuh and is normally available on the manager at:

```text
/var/ossec/ruleset/rules/
/var/ossec/ruleset/decoders/
/var/ossec/etc/lists/
```

## Runtime Integration

Point the backend at the real Wazuh alerts log before starting the app:

```powershell
$env:WAZUH_ALERT_LOG_PATH = "\\wazuh-manager\ossec\logs\alerts\alerts.json"
```

On a Linux Wazuh manager, the source path is normally:

```text
/var/ossec/logs/alerts/alerts.json
```

The app does not reimplement the Wazuh rule engine. It reads alerts produced by the official Wazuh manager, then enriches file-related alerts with YARA verification.

## Reference Copy

To keep a local reference copy of the official Wazuh ruleset in this repo, run:

```powershell
.\backend\rules\wazuh\sync_official_ruleset.ps1
```

This downloads `rules`, `decoders`, and `lists` from `https://github.com/wazuh/wazuh-ruleset` into `backend/rules/wazuh/official`.

The reference copy is for auditability and review. Do not point this app at those XML files as if they were alert logs.

## Optional Custom Rules

`optional_custom/capstone_malware_behavior_rules.xml` contains project-specific behavior rules. These are no longer the primary detection source. Install them only if you want extra local coverage on top of the official Wazuh ruleset.

```bash
sudo cp optional_custom/capstone_malware_behavior_rules.xml /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
```
