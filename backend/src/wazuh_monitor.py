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

    def extract_file_path(self, alert):
        candidate_paths = [
            alert.get("syscheck", {}).get("path"),
            alert.get("file", {}).get("path"),
            alert.get("data", {}).get("file"),
            alert.get("data", {}).get("path"),
            alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetFilename"),
        ]
        for candidate in candidate_paths:
            if isinstance(candidate, str) and candidate.strip():
                return os.path.normpath(candidate)
        return None

    def normalize_event(self, alert):
        rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
        agent = alert.get("agent", {}) if isinstance(alert.get("agent"), dict) else {}
        description = rule.get("description") or "Unknown Wazuh rule"
        level = rule.get("level", "n/a")
        groups = rule.get("groups", [])
        file_path = self.extract_file_path(alert)
        agent_name = agent.get("name") or "standalone-agent"
        file_suffix = f" | File: {file_path}" if file_path else ""
        message = f"[Wazuh ALERT] Level {level} | Agent: {agent_name} | Rule: {description}{file_suffix}"

        return {
            "message": message,
            "level": level if isinstance(level, int) else 0,
            "file_path": file_path,
            "groups": groups if isinstance(groups, list) else [],
            "kind": "alert",
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
