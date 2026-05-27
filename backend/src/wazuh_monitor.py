import json
import os
import time
from threading import Thread


class WazuhMonitor(Thread):
    def __init__(self, log_path, callback=None, replay_existing=True):
        super().__init__()
        self.daemon = True
        self.log_path = log_path
        self.callback = callback
        self._is_running = False
        self._waiting_emitted = False
        self.replay_existing = replay_existing

    def emit(self, payload):
        if self.callback:
            self.callback(payload)

    def get_nested(self, source, path):
        current = source
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    def first_value(self, alert, paths):
        for path in paths:
            value = self.get_nested(alert, path)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, int):
                return value
        return None

    def extract_file_path(self, alert):
        candidate = self.first_value(alert, [
            ["syscheck", "path"],
            ["file", "path"],
            ["data", "file"],
            ["data", "path"],
            ["data", "win", "eventdata", "targetFilename"],
            ["win", "eventdata", "targetFilename"],
        ])
        if isinstance(candidate, str):
            return os.path.normpath(candidate)
        return None

    def extract_alert_fields(self, alert):
        return {
            "rule_id": self.first_value(alert, [["rule", "id"]]),
            "rule_description": self.first_value(alert, [["rule", "description"]]),
            "agent_name": self.first_value(alert, [["agent", "name"]]),
            "agent_id": self.first_value(alert, [["agent", "id"]]),
            "process_id": self.first_value(alert, [
                ["data", "win", "eventdata", "processId"],
                ["data", "win", "eventdata", "processID"],
                ["data", "win", "eventdata", "newProcessId"],
                ["win", "eventdata", "processId"],
                ["win", "eventdata", "newProcessId"],
                ["process", "pid"],
            ]),
            "process_guid": self.first_value(alert, [
                ["data", "win", "eventdata", "processGuid"],
                ["win", "eventdata", "processGuid"],
            ]),
            "process_image": self.first_value(alert, [
                ["data", "win", "eventdata", "image"],
                ["data", "win", "eventdata", "newProcessName"],
                ["win", "eventdata", "image"],
                ["win", "eventdata", "newProcessName"],
                ["process", "name"],
            ]),
            "parent_process_image": self.first_value(alert, [
                ["data", "win", "eventdata", "parentImage"],
                ["data", "win", "eventdata", "parentProcessName"],
                ["win", "eventdata", "parentImage"],
                ["win", "eventdata", "parentProcessName"],
            ]),
            "command_line": self.first_value(alert, [
                ["data", "win", "eventdata", "commandLine"],
                ["data", "win", "eventdata", "processCommandLine"],
                ["win", "eventdata", "commandLine"],
                ["win", "eventdata", "processCommandLine"],
                ["process", "command_line"],
            ]),
            "destination_ip": self.first_value(alert, [
                ["data", "win", "eventdata", "destinationIp"],
                ["data", "win", "eventdata", "DestinationIp"],
                ["data", "win", "eventdata", "destinationIP"],
                ["win", "eventdata", "destinationIp"],
                ["win", "eventdata", "DestinationIp"],
                ["win", "eventdata", "destinationIP"],
                ["data", "dstip"],
                ["data", "dst_ip"],
                ["data", "dest_ip"],
                ["data", "destination_ip"],
            ]),
            "destination_hostname": self.first_value(alert, [
                ["data", "win", "eventdata", "destinationHostname"],
                ["data", "win", "eventdata", "DestinationHostname"],
                ["win", "eventdata", "destinationHostname"],
                ["win", "eventdata", "DestinationHostname"],
            ]),
            "destination_port": self.first_value(alert, [
                ["data", "win", "eventdata", "destinationPort"],
                ["data", "win", "eventdata", "DestinationPort"],
                ["win", "eventdata", "destinationPort"],
                ["win", "eventdata", "DestinationPort"],
                ["data", "dstport"],
                ["data", "dst_port"],
                ["data", "dest_port"],
                ["data", "destination_port"],
            ]),
            "registry_key": self.first_value(alert, [
                ["data", "win", "eventdata", "targetObject"],
                ["win", "eventdata", "targetObject"],
                ["syscheck", "path"],
            ]),
            "registry_value": self.first_value(alert, [
                ["data", "win", "eventdata", "details"],
                ["win", "eventdata", "details"],
            ]),
        }

    def normalize_event(self, alert):
        rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
        agent = alert.get("agent", {}) if isinstance(alert.get("agent"), dict) else {}
        description = rule.get("description") or "Unknown Wazuh rule"
        level = rule.get("level", "n/a")
        groups = rule.get("groups", [])
        mitre = rule.get("mitre", {})
        file_path = self.extract_file_path(alert)
        fields = self.extract_alert_fields(alert)
        agent_name = agent.get("name") or "standalone-agent"
        file_suffix = f" | File: {file_path}" if file_path else ""
        message = f"[Wazuh ALERT] Level {level} | Agent: {agent_name} | Rule: {description}{file_suffix}"

        return {
            "message": message,
            "level": level if isinstance(level, int) else 0,
            "file_path": file_path,
            "groups": groups if isinstance(groups, list) else [],
            "mitre": mitre if isinstance(mitre, dict) else {},
            "fields": fields,
            "kind": "alert",
            "username": alert.get("username"),
        }

    def emit_status(self, message):
        self.emit({
            "message": message,
            "level": 0,
            "file_path": None,
            "groups": [],
            "kind": "status",
        })

    def handle_line(self, line):
        try:
            alert = json.loads(line.strip())
        except json.JSONDecodeError:
            self.emit_status(f"Skipped malformed Wazuh alert line: {line.strip()[:120]}")
            return

        if not isinstance(alert, dict):
            return

        self.emit(self.normalize_event(alert))

    def run(self):
        self._is_running = True

        while self._is_running and not os.path.exists(self.log_path):
            if not self._waiting_emitted:
                self.emit_status(f"Waiting for Wazuh alerts log ({self.log_path}) to be created...")
                self._waiting_emitted = True
            time.sleep(1)

        if not self._is_running:
            return

        self.emit_status(f"Monitoring Wazuh alerts log: {os.path.abspath(self.log_path)}")

        with open(self.log_path, "r", encoding="utf-8") as file_handle:
            if self.replay_existing:
                replayed = 0
                for existing_line in file_handle:
                    if not self._is_running:
                        return
                    if existing_line.strip():
                        self.handle_line(existing_line)
                        replayed += 1
                self.emit_status(f"Replayed {replayed} existing Wazuh alert entries.")
            else:
                file_handle.seek(0, os.SEEK_END)

            while self._is_running:
                line = file_handle.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                if line.strip():
                    self.handle_line(line)

        self.emit_status("Wazuh event monitoring stopped.")
        self._is_running = False

    def stop(self):
        self._is_running = False
