import json
from datetime import datetime
from pathlib import Path


alert = {
    "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
    "agent": {
        "name": "win-lab-endpoint",
    },
    "rule": {
        "level": 10,
        "description": "Suspicious PowerShell persistence behavior",
        "groups": ["sysmon", "malware", "persistence"],
    },
    "syscheck": {
        "path": r"C:\Users\Public\update.ps1",
    },
}

log_path = Path("logs") / "wazuh_alerts.jsonl"
log_path.parent.mkdir(parents=True, exist_ok=True)

with open(log_path, "a", encoding="utf-8") as file_handle:
    file_handle.write(json.dumps(alert) + "\n")

print(f"[{datetime.now().strftime('%H:%M:%S')}] Mock Wazuh alert appended to {log_path}.")
