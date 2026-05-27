# Wazuh Rules

This project can consume alerts from an official Wazuh manager when one is available. Full Wazuh detection should run inside a real Wazuh manager using its default ruleset, and this app should consume the manager's generated alerts.

## Simple Default

For a low-friction demo or local endpoint test, use an existing Wazuh `alerts.json` or JSONL export. Press the Wazuh start button, choose the alert log file, and the app will replay existing alert entries and continue tailing new entries.

This keeps the app honest: Wazuh detection is still produced by Wazuh, while this project focuses on alert ingestion, visualization, YARA verification, and response actions.

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

## Official CLI Setup Helper

The official quickstart path installs the Wazuh central components on a Linux host. From this Windows project folder, you can run the helper below against a Linux VM/server that you can access over SSH:

The app can also trigger this flow from the Wazuh start button: when no manager/alerts bridge is connected, enter the Linux manager host, SSH user, and SSH port in the prompts. The backend starts the same official CLI helper in the background, connects the Windows agent, starts the alerts bridge, and then starts Wazuh monitoring.

```powershell
.\scripts\install_wazuh_manager_cli.ps1 -HostName <LINUX_MANAGER_IP> -User <SSH_USER> -InstallCapstoneRules
```

Then connect this Windows endpoint as a Wazuh agent:

```powershell
.\scripts\connect_wazuh_windows_agent.ps1 -Manager <LINUX_MANAGER_IP>
```

Finally, bridge the manager alerts file into this app:

```powershell
.\scripts\bridge_wazuh_alerts_to_local.ps1 -HostName <LINUX_MANAGER_IP> -User <SSH_USER>
```

Start the backend in another PowerShell window with:

```powershell
$env:WAZUH_ALERT_LOG_PATH = "C:\Users\ybi65\OneDrive\Desktop\capstone\logs\wazuh_alerts.jsonl"
$env:WAZUH_ALLOW_ALERT_LOG_BRIDGE = "1"
python .\backend\main.py
```

## Local WSL Manager Option

If you want to run the Wazuh manager locally instead of using a separate Linux VM/server, use WSL Ubuntu as the Linux host:

The app can launch this automatically from the Wazuh start button. Choose the local WSL option, approve the Windows UAC prompt, and follow any Ubuntu first-run prompts that Windows shows.

```powershell
.\scripts\setup_wazuh_manager_wsl.ps1 -Distro Ubuntu
```

If Ubuntu is not installed yet, run from an elevated PowerShell:

```powershell
.\scripts\setup_wazuh_manager_wsl.ps1 -Distro Ubuntu -InstallDistro
```

After Wazuh is installed inside WSL, bridge the manager alerts file into this app:

```powershell
.\scripts\bridge_wazuh_alerts_from_wsl.ps1 -Distro Ubuntu
```

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
