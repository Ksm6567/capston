import os
import yara
import time
from PyQt6.QtCore import QThread, pyqtSignal

class YaraScanner(QThread):
    scan_result = pyqtSignal(str)
    scan_finished = pyqtSignal()
    
    def __init__(self, rules_path="rules/sample.yar", target_path="."):
        super().__init__()
        self.rules_path = rules_path
        self.target_path = target_path
        self._is_running = False
        self.scanned_files = {}

    def run(self):
        self._is_running = True
        
        if not os.path.exists(self.rules_path):
            self.scan_result.emit(f"Error: Yara rule file not found ({os.path.abspath(self.rules_path)})")
            self.scan_finished.emit()
            return
            
        try:
            self.scan_result.emit(f"Compiling Yara rules from: {self.rules_path}")
            rules = yara.compile(filepath=self.rules_path)
        except Exception as e:
            self.scan_result.emit(f"Failed to compile Yara rules: {str(e)}")
            self.scan_finished.emit()
            return

        self.scan_result.emit(f"Starting continuous Yara scan on directory: {os.path.abspath(self.target_path)}")

        while self._is_running:
            for root, dirs, files in os.walk(self.target_path):
                if not self._is_running:
                    break
                    
                # Skip hidden directories, virtual environments, and the cache folder
                if 'venv' in root or '.git' in root or '.gemini' in root or '__pycache__' in root:
                    continue
                    
                for file in files:
                    if not self._is_running:
                        break
                    file_path = os.path.join(root, file)
                    
                    try:
                        mtime = os.path.getmtime(file_path)
                        # Only scan if the file is new or modified
                        if file_path not in self.scanned_files or self.scanned_files[file_path] != mtime:
                            matches = rules.match(file_path)
                            self.scanned_files[file_path] = mtime
                            
                            if matches:
                                match_names = ", ".join([m.rule for m in matches])
                                self.scan_result.emit(f"[💀 Yara DETECT!] File: {file_path} | Rules Matched: {match_names}")
                    except Exception:
                        # Ignore permission errors or unreadable files
                        pass
                        
            # Wait for 1 second before scanning again
            if self._is_running:
                time.sleep(1)

        self.scan_result.emit("Yara scan stopped.")
        self.scan_finished.emit()
        self._is_running = False

    def stop(self):
        self._is_running = False
