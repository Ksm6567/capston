import os
import yara
import time
from threading import Thread

class YaraScanner(Thread):
    def __init__(self, rules_path="rules/sample.yar", target_path=".", callback=None, on_finished=None):
        super().__init__()
        self.daemon = True
        self.rules_path = rules_path
        self.target_path = target_path
        self._is_running = False
        self.scanned_files = {}
        self.callback = callback
        self.on_finished = on_finished

    def run(self):
        self._is_running = True
        
        if not os.path.exists(self.rules_path):
            if self.callback:
                self.callback(f"Error: Yara rule file not found ({os.path.abspath(self.rules_path)})")
            if self.on_finished:
                self.on_finished()
            return
            
        try:
            if self.callback:
                self.callback(f"Compiling Yara rules from: {self.rules_path}")
            rules = yara.compile(filepath=self.rules_path)
        except Exception as e:
            if self.callback:
                self.callback(f"Failed to compile Yara rules: {str(e)}")
            if self.on_finished:
                self.on_finished()
            return

        if self.callback:
            self.callback(f"Starting continuous Yara scan on directory: {os.path.abspath(self.target_path)}")

        while self._is_running:
            for root, dirs, files in os.walk(self.target_path):
                if not self._is_running:
                    break
                    
                # Skip hidden directories, virtual environments, and the cache folder
                if 'venv' in root or '.git' in root or '.gemini' in root or '__pycache__' in root or 'node_modules' in root:
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
                                if self.callback:
                                    self.callback(f"[💀 Yara DETECT!] File: {file_path} | Rules Matched: {match_names}")
                    except Exception:
                        pass
                        
            if self._is_running:
                time.sleep(1)

        if self.callback:
            self.callback("Yara scan stopped.")
        if self.on_finished:
            self.on_finished()
        self._is_running = False

    def stop(self):
        self._is_running = False
