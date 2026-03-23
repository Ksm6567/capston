import os
import json
import time
from PyQt6.QtCore import QThread, pyqtSignal

class SuricataMonitor(QThread):
    new_alert = pyqtSignal(str)
    
    def __init__(self, log_path="eve.json"):
        super().__init__()
        self.log_path = log_path
        self._is_running = False

    def run(self):
        self._is_running = True
        
        # If the file does not exist, wait for it
        if not os.path.exists(self.log_path):
            self.new_alert.emit(f"Waiting for Suricata log ({self.log_path}) to be created...")
            while self._is_running and not os.path.exists(self.log_path):
                time.sleep(2)
                
        if not self._is_running:
            return

        self.new_alert.emit(f"Monitoring Suricata log: {os.path.abspath(self.log_path)}")

        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                # Suricata eve.json can be huge, jump to the end to only see new alerts
                f.seek(0, 2)
                
                while self._is_running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                        
                    try:
                        record = json.loads(line)
                        event_type = record.get("event_type", "unknown")
                        
                        if event_type == "alert":
                            alert_msg = record.get('alert', {}).get('signature', 'Unknown Alert')
                            src_ip = record.get('src_ip', '')
                            dest_ip = record.get('dest_ip', '')
                            
                            format_msg = f"[🚨 Suricata ALERT] {alert_msg} | {src_ip} -> {dest_ip}"
                            self.new_alert.emit(format_msg)
                        elif event_type == "stats":
                            # Optionally ignore background stats
                            pass
                        
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            self.new_alert.emit(f"Error reading Suricata log: {str(e)}")

    def stop(self):
        self._is_running = False
