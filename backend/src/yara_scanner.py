import hashlib
import os
import time
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread

import yara


_RULE_CACHE = {}
_RULE_CACHE_LOCK = Lock()


class YaraScanner(Thread):
    RULE_BATCH_SIZE = 64
    TARGET_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".psm1",
        ".vbs", ".js", ".jse", ".hta", ".jar", ".lnk", ".docm", ".xlsm", ".pptm",
        ".iso", ".img", ".zip", ".7z", ".rar", ".txt",
    }
    IGNORED_DIR_NAMES = {
        ".git", ".gemini", "__pycache__", "node_modules", "venv", "logs", "$recycle.bin",
        "quarantine", "system volume information", "winsxs", "temp", "tmp",
    }
    IGNORED_FILE_NAMES = {
        "eve.json", "out.txt", "ws_out.txt", "test_output.txt",
    }
    IGNORED_SUFFIXES = {".yar", ".yara", ".pyc", ".sqlite", ".sqlite-journal", ".log"}
    MAX_FILE_SIZE = 50 * 1024 * 1024
    POLL_INTERVAL = 10

    def __init__(
        self,
        rules_path="rules/enhanced_rules.yar",
        target_path=None,
        target_paths=None,
        callback=None,
        on_finished=None,
        monitor_after_initial=True,
    ):
        super().__init__()
        self.daemon = True
        self.rules_path = rules_path
        self.target_path = target_path
        self.target_paths = target_paths or []
        self._is_running = False
        self.callback = callback
        self.on_finished = on_finished
        self.file_state = {}
        self.monitor_after_initial = monitor_after_initial

    def emit(self, message, details=None):
        if self.callback:
            try:
                self.callback(message, details)
            except TypeError:
                self.callback(message)

    def get_scan_roots(self):
        if self.target_paths:
            return [path for path in self.target_paths if path]

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

    def is_rule_file(self, path):
        if path.suffix.lower() not in {".yar", ".yara"}:
            return False

        name = path.name.lower()
        return not (
            name == "index.yar" or
            name == "index_w_mobile.yar" or
            name.endswith("_index.yar")
        )

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

    def rule_source_signature(self, source_path):
        if source_path.is_dir():
            rule_files = sorted(
                path for path in source_path.rglob("*")
                if path.is_file() and self.is_rule_file(path)
            )
            return tuple((str(path), path.stat().st_mtime_ns, path.stat().st_size) for path in rule_files)

        stat = source_path.stat()
        return ((str(source_path), stat.st_mtime_ns, stat.st_size),)

    def get_rule_files(self, source_path):
        return sorted(
            path for path in source_path.rglob("*")
            if path.is_file() and self.is_rule_file(path)
        )

    def build_rule_namespace(self, index, rule_file):
        safe_name = "".join(
            char if char.isalnum() or char == "_" else "_"
            for char in rule_file.stem
        )
        return f"rule_{index:04d}_{safe_name[:48]}"

    def compile_rule_batch(self, indexed_rule_files, skipped_rules):
        filepaths = {
            self.build_rule_namespace(index, rule_file): str(rule_file)
            for index, rule_file in indexed_rule_files
        }
        try:
            return [yara.compile(filepaths=filepaths)]
        except Exception as exc:
            if len(indexed_rule_files) == 1:
                _, rule_file = indexed_rule_files[0]
                error = str(exc).strip() or exc.__class__.__name__
                skipped_rules.append((rule_file, error))
                return []

            midpoint = len(indexed_rule_files) // 2
            return (
                self.compile_rule_batch(indexed_rule_files[:midpoint], skipped_rules) +
                self.compile_rule_batch(indexed_rule_files[midpoint:], skipped_rules)
            )

    def compile_directory_rules(self, source_path):
        rule_files = self.get_rule_files(source_path)
        compiled_rules = []
        skipped_rules = []
        indexed_rule_files = list(enumerate(rule_files))

        for start in range(0, len(indexed_rule_files), self.RULE_BATCH_SIZE):
            batch = indexed_rule_files[start:start + self.RULE_BATCH_SIZE]
            compiled_rules.extend(self.compile_rule_batch(batch, skipped_rules))

        if skipped_rules:
            examples = "; ".join(
                f"{rule_file.name}: {error}"
                for rule_file, error in skipped_rules[:3]
            )
            suffix = "" if len(skipped_rules) <= 3 else f"; +{len(skipped_rules) - 3} more"
            self.emit(
                f"[Yara VERIFY] Ignored {len(skipped_rules)} incompatible Yara rule file(s): {examples}{suffix}"
            )

        return compiled_rules

    def compile_rule_sources(self):
        source_path = Path(self.rules_path)
        signature = self.rule_source_signature(source_path)
        cache_key = (str(source_path.resolve()), signature)

        with _RULE_CACHE_LOCK:
            cached_rules = _RULE_CACHE.get(cache_key)
            if cached_rules is not None:
                return cached_rules

            resolved_source = str(source_path.resolve())
            for existing_key in list(_RULE_CACHE):
                if existing_key[0] == resolved_source:
                    _RULE_CACHE.pop(existing_key, None)

            if source_path.is_dir():
                compiled_rules = self.compile_directory_rules(source_path)
                if not compiled_rules:
                    raise ValueError(f"No valid Yara rule files found in {source_path}")
            else:
                compiled_rules = [yara.compile(filepath=self.rules_path)]

            _RULE_CACHE[cache_key] = compiled_rules
        return compiled_rules

    def match_file(self, compiled_rules, file_path):
        matches = []
        for rules in compiled_rules:
            matches.extend(rules.match(file_path))
        return matches

    def calculate_sha256(self, file_path):
        digest = hashlib.sha256()
        try:
            with open(file_path, "rb") as file_handle:
                for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return None

    def build_match_details(self, file_path, stat, matches):
        return {
            "kind": "yara_match",
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            "sha256": self.calculate_sha256(file_path),
            "rules_path": self.rules_path,
            "matches": [
                {
                    "rule": match.rule,
                    "namespace": getattr(match, "namespace", None),
                    "tags": list(getattr(match, "tags", []) or []),
                    "meta": dict(getattr(match, "meta", {}) or {}),
                }
                for match in matches
            ],
        }

    def scan_files(self, compiled_rules, roots, only_changed):
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
                matches = self.match_file(compiled_rules, file_path)
            except Exception:
                continue

            if matches:
                matched += 1
                match_names = ", ".join(match.rule for match in matches)
                details = self.build_match_details(file_path, stat, matches)
                self.emit(f"[Yara DETECT] File: {file_path} | Rules Matched: {match_names}", details)

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
            compiled_rules = self.compile_rule_sources()
        except Exception as e:
            self.emit(f"Failed to compile Yara rules: {str(e)}")
            if self.on_finished:
                self.on_finished()
            return

        roots = self.get_scan_roots()
        root_summary = ", ".join(roots)
        self.emit(f"Starting initial Yara scan on: {root_summary}")
        scanned, matched = self.scan_files(compiled_rules, roots, only_changed=False)
        self.emit(f"Initial Yara scan complete. Scanned {scanned} files, matched {matched} files.")

        if not self.monitor_after_initial:
            if self.on_finished:
                self.on_finished()
            self._is_running = False
            return

        self.emit("Initial Yara scan finished. Continuing to monitor selected folders for file changes.")

        while self._is_running:
            scanned, matched = self.scan_files(compiled_rules, roots, only_changed=True)
            if scanned:
                self.emit(f"Yara incremental scan checked {scanned} changed files, matched {matched} files.")
            time.sleep(self.POLL_INTERVAL)

        self.emit("Yara scan stopped.")
        if self.on_finished:
            self.on_finished()
        self._is_running = False

    def stop(self):
        self._is_running = False


def scan_file_with_rules(rules_path, file_path):
    normalized_path = os.path.normpath(file_path)

    if not os.path.exists(rules_path):
        return {
            "status": "error",
            "message": f"Yara rule file not found: {os.path.abspath(rules_path)}",
            "matches": [],
        }

    if not os.path.isfile(normalized_path):
        return {
            "status": "missing",
            "message": f"Target file not found for verification: {normalized_path}",
            "matches": [],
        }

    try:
        scanner = YaraScanner(rules_path=rules_path)
        compiled_rules = scanner.compile_rule_sources()
        matches = scanner.match_file(compiled_rules, normalized_path)
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Yara verification failed for {normalized_path}: {exc}",
            "matches": [],
        }

    return {
        "status": "matched" if matches else "clean",
        "message": f"Yara verification completed for {normalized_path}",
        "matches": [match.rule for match in matches],
    }
