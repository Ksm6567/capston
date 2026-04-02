import os
import time
from threading import Thread

import yara


class YaraScanner(Thread):
    TARGET_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".psm1",
        ".vbs", ".js", ".jse", ".hta", ".jar", ".lnk", ".docm", ".xlsm", ".pptm",
        ".iso", ".img", ".zip", ".7z", ".rar", ".txt",
    }
    IGNORED_DIR_NAMES = {
        ".git", ".gemini", "__pycache__", "node_modules", "venv", "logs", "$recycle.bin",
        "system volume information", "winsxs", "temp", "tmp",
    }
    IGNORED_FILE_NAMES = {
        "eve.json", "out.txt", "ws_out.txt", "test_output.txt",
    }
    IGNORED_SUFFIXES = {".yar", ".yara", ".pyc", ".sqlite", ".sqlite-journal", ".log"}
    MAX_FILE_SIZE = 50 * 1024 * 1024
    POLL_INTERVAL = 10

    def __init__(self, rules_path="rules/enhanced_rules.yar", target_path=None, callback=None, on_finished=None):
        super().__init__()
        self.daemon = True
        self.rules_path = rules_path
        self.target_path = target_path
        self._is_running = False
        self.callback = callback
        self.on_finished = on_finished
        self.file_state = {}

    def emit(self, message):
        if self.callback:
            self.callback(message)

    def get_scan_roots(self):
        if self.target_path:
            return [self.target_path]

        roots = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                roots.append(drive)
        return roots

    def should_skip_directory(self, path):
        normalized = path.lower()
        return any(part in self.IGNORED_DIR_NAMES for part in normalized.split(os.sep))

    def should_scan_file(self, file_path):
        lower_path = file_path.lower()
        file_name = os.path.basename(lower_path)
        _, ext = os.path.splitext(lower_path)

        if file_name in self.IGNORED_FILE_NAMES:
            return False
        if ext in self.IGNORED_SUFFIXES:
            return False
        if ext not in self.TARGET_EXTENSIONS:
            return False

        try:
            return os.path.getsize(file_path) <= self.MAX_FILE_SIZE
        except OSError:
            return False

    def iter_candidate_files(self, roots):
        for scan_root in roots:
            if not os.path.exists(scan_root):
                continue

            for root, dirs, files in os.walk(scan_root):
                if not self._is_running:
                    return

                dirs[:] = [d for d in dirs if not self.should_skip_directory(os.path.join(root, d))]

                for file_name in files:
                    if not self._is_running:
                        return

                    file_path = os.path.join(root, file_name)
                    if self.should_scan_file(file_path):
                        yield file_path

    def scan_files(self, rules, roots, only_changed):
        matched = 0
        scanned = 0
        seen = set()

        for file_path in self.iter_candidate_files(roots):
            seen.add(file_path)
            try:
                stat = os.stat(file_path)
            except OSError:
                continue

            state = (stat.st_mtime_ns, stat.st_size)
            previous = self.file_state.get(file_path)
            if only_changed and previous == state:
                continue

            self.file_state[file_path] = state
            scanned += 1

            try:
                matches = rules.match(file_path)
            except Exception:
                continue

            if matches:
                matched += 1
                match_names = ", ".join(match.rule for match in matches)
                self.emit(f"[Yara DETECT] File: {file_path} | Rules Matched: {match_names}")

        stale_paths = [path for path in self.file_state if path not in seen]
        for stale_path in stale_paths:
            self.file_state.pop(stale_path, None)

        return scanned, matched

    def run(self):
        self._is_running = True

        if not os.path.exists(self.rules_path):
            self.emit(f"Error: Yara rule file not found ({os.path.abspath(self.rules_path)})")
            if self.on_finished:
                self.on_finished()
            return

        try:
            self.emit(f"Compiling Yara rules from: {self.rules_path}")
            rules = yara.compile(filepath=self.rules_path)
        except Exception as e:
            self.emit(f"Failed to compile Yara rules: {str(e)}")
            if self.on_finished:
                self.on_finished()
            return

        roots = self.get_scan_roots()
        root_summary = ", ".join(roots)
        self.emit(f"Starting initial full-drive Yara scan on: {root_summary}")
        scanned, matched = self.scan_files(rules, roots, only_changed=False)
        self.emit(f"Initial Yara scan complete. Scanned {scanned} files, matched {matched} files.")

        while self._is_running:
            scanned, matched = self.scan_files(rules, roots, only_changed=True)
            if scanned:
                self.emit(f"Yara incremental scan checked {scanned} changed files, matched {matched} files.")
            time.sleep(self.POLL_INTERVAL)

        self.emit("Yara scan stopped.")
        if self.on_finished:
            self.on_finished()
        self._is_running = False

    def stop(self):
        self._is_running = False
