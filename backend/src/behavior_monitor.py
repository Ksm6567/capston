import ipaddress
import json
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime
from threading import Thread


SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
RULESET_REFERENCE = "backend/rules/wazuh/official/rules/0595-win-sysmon_rules.xml"


class BehaviorMonitor(Thread):
    """Local behavior detector using Sysmon when available.

    The emitted event shape intentionally matches the old Wazuh alert adapter so
    the existing incident and response pipeline can keep working.
    """

    def __init__(self, callback=None, poll_interval=2.0):
        super().__init__()
        self.daemon = True
        self.callback = callback
        self.poll_interval = poll_interval
        self._is_running = False
        self.sysmon_available = False
        self.last_record_id = 0
        self.seen_processes = set()
        self.seen_alerts = set()
        self.shell_launches = deque(maxlen=100)

    def emit(self, payload):
        if self.callback:
            self.callback(payload)

    def emit_status(self, message):
        self.emit({
            "kind": "status",
            "message": message,
            "level": 0,
            "file_path": None,
            "groups": [],
        })

    def get_status(self):
        return {
            "ready": True,
            "mode": "sysmon" if self.sysmon_available else "process_snapshot",
            "event_log": SYSMON_LOG_NAME if self.sysmon_available else None,
            "rules_reference": RULESET_REFERENCE,
        }

    def run_command(self, command, timeout=10):
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def check_sysmon_available(self):
        if os.name != "nt":
            return False
        try:
            completed = self.run_command(["wevtutil.exe", "gl", SYSMON_LOG_NAME], timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def get_latest_sysmon_record_id(self):
        try:
            completed = self.run_command(
                ["wevtutil.exe", "qe", SYSMON_LOG_NAME, "/rd:true", "/c:1", "/f:xml"],
                timeout=8,
            )
        except (OSError, subprocess.TimeoutExpired):
            return 0
        if completed.returncode != 0 or not completed.stdout.strip():
            return 0
        events = self.parse_event_xml(completed.stdout)
        if not events:
            return 0
        return int(events[0].get("record_id") or 0)

    def query_sysmon_events(self):
        query = f"*[System[EventRecordID > {int(self.last_record_id)}]]"
        try:
            completed = self.run_command(
                ["wevtutil.exe", "qe", SYSMON_LOG_NAME, f"/q:{query}", "/f:xml", "/c:60"],
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if completed.returncode != 0 or not completed.stdout.strip():
            return []
        return self.parse_event_xml(completed.stdout)

    def parse_event_xml(self, text):
        xml_text = text.strip()
        if not xml_text:
            return []
        if not xml_text.startswith("<Events"):
            xml_text = f"<Events>{xml_text}</Events>"
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []

        events = []
        for event_node in list(root):
            system = self.child(event_node, "System")
            event_data = self.child(event_node, "EventData")
            if system is None:
                continue
            event_id = self.node_text(self.child(system, "EventID"))
            record_id = self.node_text(self.child(system, "EventRecordID"))
            provider = self.child(system, "Provider")
            time_created = self.child(system, "TimeCreated")
            data = {}
            if event_data is not None:
                for item in list(event_data):
                    name = self.local_attr(item, "Name")
                    if name:
                        data[name] = item.text or ""
            events.append({
                "event_id": int(event_id) if str(event_id).isdigit() else 0,
                "record_id": int(record_id) if str(record_id).isdigit() else 0,
                "provider": self.local_attr(provider, "Name") if provider is not None else "",
                "time_created": self.local_attr(time_created, "SystemTime") if time_created is not None else "",
                "data": data,
            })
        return events

    def child(self, node, name):
        if node is None:
            return None
        for item in list(node):
            if item.tag.split("}", 1)[-1] == name:
                return item
        return None

    def node_text(self, node):
        return (node.text or "").strip() if node is not None else ""

    def local_attr(self, node, name):
        if node is None:
            return ""
        return node.attrib.get(name, "")

    def poll_process_snapshot(self):
        command = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
            "ConvertTo-Json -Compress",
        ]
        try:
            completed = self.run_command(command, timeout=12)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if completed.returncode != 0 or not completed.stdout.strip():
            return []
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return []
        rows = payload if isinstance(payload, list) else [payload]
        events = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            pid = row.get("ProcessId")
            if pid in self.seen_processes:
                continue
            self.seen_processes.add(pid)
            image = row.get("ExecutablePath") or row.get("Name") or ""
            command_line = row.get("CommandLine") or ""
            if "Get-CimInstance Win32_Process" in command_line and "ConvertTo-Json" in command_line:
                continue
            events.append({
                "event_id": 1,
                "record_id": int(time.time() * 1000),
                "provider": "Win32_Process",
                "time_created": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "data": {
                    "Image": image,
                    "CommandLine": command_line,
                    "ProcessId": str(pid or ""),
                    "ParentProcessId": str(row.get("ParentProcessId") or ""),
                },
            })
        return events

    def analyze_event(self, event):
        event_id = event.get("event_id")
        data = event.get("data") or {}
        if event_id == 1:
            return self.analyze_process_create(event, data)
        if event_id == 3:
            return self.analyze_network_connection(event, data)
        if event_id == 10:
            return self.analyze_process_access(event, data)
        if event_id == 11:
            return self.analyze_file_create(event, data)
        if event_id == 13:
            return self.analyze_registry_set(event, data)
        return []

    def analyze_process_create(self, event, data):
        alerts = []
        image = data.get("Image") or data.get("NewProcessName") or ""
        command_line = data.get("CommandLine") or data.get("ProcessCommandLine") or ""
        parent = data.get("ParentImage") or data.get("ParentProcessName") or ""
        lower_cmd = command_line.lower()
        lower_image = image.lower()
        lower_parent = parent.lower()

        if self.is_shell(image):
            now = time.time()
            self.shell_launches.append(now)
            recent = [item for item in self.shell_launches if now - item <= 20]
            if len(recent) >= 8:
                alerts.append(self.build_alert(
                    event,
                    "110020",
                    "Repeated shell process launches",
                    11,
                    ["sysmon", "sysmon_event1", "shell_burst", "execution"],
                    ["T1059"],
                    f"Repeated shell process launches observed ({len(recent)} in 20s)",
                ))

        if self.is_powershell(image) and re.search(
            r"(?i)(\s-|/)(enc|encodedcommand|w\s+hidden|windowstyle\s+hidden|executionpolicy\s+bypass)\b|"
            r"frombase64string|downloadstring|invoke-expression|\biex\b|net\.webclient",
            command_line,
        ):
            alerts.append(self.build_alert(
                event,
                "110001",
                "Suspicious PowerShell execution pattern",
                12,
                ["sysmon", "sysmon_event1", "powershell", "defense_evasion"],
                ["T1059.001", "T1027"],
                "Suspicious PowerShell execution pattern",
            ))

        if re.search(
            r"(?i)vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog|"
            r"bcdedit\s+/set\s+\{?default\}?\s+recoveryenabled\s+no|"
            r"bcdedit\s+/set\s+\{?default\}?\s+bootstatuspolicy\s+ignoreallfailures",
            command_line,
        ):
            alerts.append(self.build_alert(
                event,
                "110015",
                "Ransomware-style recovery inhibition command",
                13,
                ["sysmon", "sysmon_event1", "ransomware", "impact"],
                ["T1490"],
                "Ransomware-style recovery inhibition command",
            ))

        if self.is_lolbin(image) and re.search(
            r"(?i)https?://|ftp://|javascript:|vbscript:|scrobj\.dll|/i:https?://|http.*\.sct|urlcache",
            command_line,
        ):
            alerts.append(self.build_alert(
                event,
                "110003",
                "Suspicious LOLBin network or script execution",
                12,
                ["sysmon", "sysmon_event1", "lolbin", "command_and_control"],
                ["T1218", "T1105"],
                "Suspicious LOLBin network or script execution",
            ))

        if re.search(r"\\(winword|excel|powerpnt|outlook)\.exe$", lower_parent) and re.search(
            r"\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$",
            lower_image,
        ):
            alerts.append(self.build_alert(
                event,
                "110014",
                "Office process spawned suspicious child process",
                12,
                ["sysmon", "sysmon_event1", "office", "execution"],
                ["T1204.002", "T1059"],
                "Office process spawned suspicious child process",
            ))

        if re.search(r"\\(appdata\\local\\temp|appdata\\roaming|programdata|users\\public)\\", lower_image):
            alerts.append(self.build_alert(
                event,
                "110021",
                "Executable started from a user-writable high-risk path",
                10,
                ["sysmon", "sysmon_event1", "malware_dropper", "execution"],
                ["T1204", "T1105"],
                "Executable started from a user-writable high-risk path",
            ))

        return alerts

    def analyze_network_connection(self, event, data):
        image = data.get("Image") or data.get("SourceImage") or ""
        destination_ip = data.get("DestinationIp") or data.get("destinationIp") or ""
        if not self.is_script_or_lolbin(image) or not self.is_public_ip(destination_ip):
            return []
        return [self.build_alert(
            event,
            "110004",
            "Suspicious Windows script or LOLBin network connection",
            10,
            ["sysmon", "sysmon_event3", "network", "command_and_control"],
            ["T1105", "T1071"],
            "Suspicious Windows script or LOLBin network connection",
        )]

    def analyze_process_access(self, event, data):
        target = (data.get("TargetImage") or "").lower()
        source = data.get("SourceImage") or data.get("Image") or ""
        access = data.get("GrantedAccess") or ""
        if not target.endswith("\\lsass.exe"):
            return []
        if not self.is_script_or_lolbin(source) and not re.search(r"(?i)\\(procdump|mimikatz|nanodump|dumpert|taskmgr)\.exe$", source):
            return []
        if not re.search(r"(?i)0x(1f0fff|1fffff|143a|1410|1010|1038|40|1400|1000)", access):
            return []
        return [self.build_alert(
            event,
            "110011",
            "Potential credential dumping: process accessed LSASS",
            14,
            ["sysmon", "sysmon_event_10", "credential_access", "lsass"],
            ["T1003.001"],
            "Potential credential dumping: process accessed LSASS",
        )]

    def analyze_file_create(self, event, data):
        target = data.get("TargetFilename") or ""
        lower_target = target.lower()
        if re.search(r"\\(start menu\\programs\\startup|startup)\\.*\.(exe|lnk|ps1|vbs|js|hta|cmd|bat|scr)$", lower_target):
            return [self.build_alert(
                event,
                "110009",
                "Suspicious startup folder artifact created",
                12,
                ["sysmon", "sysmon_event_11", "persistence", "file_create"],
                ["T1547.001"],
                "Suspicious startup folder artifact created",
                file_path=target,
            )]
        if re.search(r"\\(appdata\\roaming|appdata\\local\\temp|programdata|users\\public)\\.*\.(exe|dll|scr|ps1|vbs|js|hta|cmd|bat)$", lower_target):
            return [self.build_alert(
                event,
                "110010",
                "Executable or script dropped in user-writable high-risk path",
                11,
                ["sysmon", "sysmon_event_11", "file_create", "malware_dropper"],
                ["T1105", "T1204"],
                "Executable or script dropped in user-writable high-risk path",
                file_path=target,
            )]
        return []

    def analyze_registry_set(self, event, data):
        target = data.get("TargetObject") or ""
        details = data.get("Details") or ""
        combined = f"{target} {details}"
        if re.search(r"(?i)\\software\\microsoft\\windows\\currentversion\\(run|runonce|policies\\explorer\\run)\\", target) and re.search(
            r"(?i)powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript|appdata|programdata|temp|http|\.ps1|\.vbs|\.js|\.hta|\.scr|\.exe",
            details,
        ):
            return [self.build_alert(
                event,
                "110006",
                "Suspicious Run key persistence value",
                12,
                ["sysmon", "sysmon_event_13", "persistence", "registry"],
                ["T1547.001"],
                "Suspicious Run key persistence value",
            )]
        if re.search(r"(?i)\\microsoft\\windows defender\\.*(disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection|disablescriptscanning|puaprotection)", combined):
            return [self.build_alert(
                event,
                "110007",
                "Windows Defender protection disabled or weakened",
                13,
                ["sysmon", "sysmon_event_13", "defense_evasion", "defender"],
                ["T1562.001"],
                "Windows Defender protection disabled or weakened",
            )]
        if re.search(r"(?i)\\microsoft\\windows nt\\currentversion\\image file execution options\\[^\\]+\\debugger$", target):
            return [self.build_alert(
                event,
                "110008",
                "Image File Execution Options debugger persistence detected",
                12,
                ["sysmon", "sysmon_event_13", "persistence", "privilege_escalation"],
                ["T1546.012"],
                "Image File Execution Options debugger persistence detected",
            )]
        return []

    def build_alert(self, event, rule_id, description, level, groups, mitre_ids, message, file_path=None):
        data = event.get("data") or {}
        fields = {
            "rule_id": rule_id,
            "rule_description": description,
            "agent_name": os.environ.get("COMPUTERNAME") or "local-endpoint",
            "agent_id": "local",
            "process_id": data.get("ProcessId") or data.get("ProcessID") or data.get("SourceProcessId"),
            "process_guid": data.get("ProcessGuid") or data.get("SourceProcessGuid"),
            "process_image": data.get("Image") or data.get("SourceImage") or data.get("NewProcessName"),
            "parent_process_image": data.get("ParentImage") or data.get("ParentProcessName"),
            "command_line": data.get("CommandLine") or data.get("ProcessCommandLine"),
            "destination_ip": data.get("DestinationIp") or data.get("destinationIp"),
            "destination_hostname": data.get("DestinationHostname") or data.get("destinationHostname"),
            "destination_port": data.get("DestinationPort") or data.get("destinationPort"),
            "registry_key": data.get("TargetObject"),
            "registry_value": data.get("Details"),
        }
        fingerprint = "|".join([
            str(rule_id),
            str(event.get("record_id")),
            str(fields.get("process_id") or ""),
            str(fields.get("destination_ip") or ""),
            str(file_path or ""),
        ])
        if fingerprint in self.seen_alerts:
            return None
        self.seen_alerts.add(fingerprint)
        rule_ref = f"Wazuh ruleset reference {RULESET_REFERENCE}"
        image_hint = fields.get("process_image") or fields.get("destination_ip") or file_path or ""
        return {
            "kind": "alert",
            "message": f"[Behavior DETECT] {message} | {image_hint} | Ref: {rule_ref}",
            "level": level,
            "file_path": os.path.normpath(file_path) if file_path else None,
            "groups": groups,
            "mitre": {"technique": mitre_ids},
            "fields": fields,
        }

    def is_powershell(self, image):
        return bool(re.search(r"(?i)\\(powershell|pwsh)\.exe$|^(powershell|pwsh)\.exe$", image or ""))

    def is_shell(self, image):
        return bool(re.search(r"(?i)\\(cmd|powershell|pwsh)\.exe$|^(cmd|powershell|pwsh)\.exe$", image or ""))

    def is_lolbin(self, image):
        return bool(re.search(r"(?i)\\(mshta|rundll32|regsvr32|wscript|cscript|msiexec)\.exe$|^(mshta|rundll32|regsvr32|wscript|cscript|msiexec)\.exe$", image or ""))

    def is_script_or_lolbin(self, image):
        return self.is_shell(image) or self.is_lolbin(image)

    def is_public_ip(self, value):
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            return False
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)

    def handle_events(self, events):
        for event in events:
            if event.get("record_id", 0) > self.last_record_id:
                self.last_record_id = event["record_id"]
            for alert in self.analyze_event(event):
                if alert:
                    self.emit(alert)

    def run(self):
        self._is_running = True
        self.sysmon_available = self.check_sysmon_available()
        if self.sysmon_available:
            self.last_record_id = self.get_latest_sysmon_record_id()
            self.emit_status(
                f"Behavior detection started with Sysmon event log. Ref: {RULESET_REFERENCE}"
            )
        else:
            self.emit_status(
                "Sysmon event log was not found. Behavior detection is running in limited process snapshot mode."
            )
            self.poll_process_snapshot()

        while self._is_running:
            events = self.query_sysmon_events() if self.sysmon_available else self.poll_process_snapshot()
            self.handle_events(events)
            time.sleep(self.poll_interval)

        self.emit_status("Behavior detection stopped.")
        self._is_running = False

    def stop(self):
        self._is_running = False
