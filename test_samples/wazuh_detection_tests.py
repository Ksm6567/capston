#!/usr/bin/env python3
"""Safely test whether Wazuh detects process and network signals.

This script does not call the Capstone backend incident test APIs and does not
verify response actions. It only emits harmless endpoint activity and watches a
real Wazuh alerts log for matching alerts.

Tests:
* process: starts a short-lived Python sleep process with a unique command-line
  marker, then checks whether Wazuh alerts include that marker or PID.
* ip: attempts a short TCP connection to a documentation IP address, then checks
  whether Wazuh alerts include that destination IP.
"""

from __future__ import annotations

import argparse
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_APP_FALLBACK_LOG = PROJECT_ROOT / "logs" / "wazuh_alerts.jsonl"

WAZUH_SERVICE_CANDIDATES = ("WazuhSvc", "Wazuh", "ossec-agent")
WAZUH_ALERT_LOG_CANDIDATES = [
    os.environ.get("WAZUH_ALERT_LOG_PATH"),
    r"C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json",
    r"C:\Program Files\ossec-agent\logs\alerts\alerts.json",
    str(LOCAL_APP_FALLBACK_LOG),
]

PROCESS_MARKER_PREFIX = "CAPSTONE_WAZUH_PROCESS_DETECTION_TEST"
DEFAULT_TEST_IP = "203.0.113.10"
DEFAULT_TEST_PORT = 443


def print_section(title: str) -> None:
    print(f"\n=== {title} ===")


def print_kv(key: str, value: object) -> None:
    print(f"{key}: {value}")


def run_command(command: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def query_wazuh_service(service_names: list[str]) -> dict | None:
    if platform.system().lower() != "windows":
        return None

    for service_name in service_names:
        completed = run_command(["sc.exe", "query", service_name])
        if completed.returncode != 0:
            continue

        output = f"{completed.stdout}\n{completed.stderr}"
        state_line = next(
            (line.strip() for line in output.splitlines() if "STATE" in line.upper()),
            "STATE: unknown",
        )
        return {
            "name": service_name,
            "state": state_line,
            "running": "RUNNING" in state_line.upper(),
        }
    return None


def resolve_wazuh_alert_log(explicit_path: str | None) -> tuple[Path | None, bool]:
    candidates = [explicit_path] if explicit_path else WAZUH_ALERT_LOG_CANDIDATES
    for candidate in candidates:
        if not candidate:
            continue

        path = Path(candidate)
        if path.exists():
            normalized = str(path).lower()
            is_real_wazuh_log = "ossec-agent" in normalized or bool(os.environ.get("WAZUH_ALERT_LOG_PATH"))
            return path.resolve(), is_real_wazuh_log

    if explicit_path:
        return Path(explicit_path).resolve(), True
    return None, False


def file_size_or_zero(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def read_new_text(path: Path, start_offset: int) -> str:
    try:
        size = path.stat().st_size
        offset = 0 if size < start_offset else start_offset
        with path.open("rb") as file_handle:
            file_handle.seek(offset)
            return file_handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def find_matching_line(text: str, needles: list[str]) -> tuple[str | None, str | None]:
    for line in text.splitlines():
        for needle in needles:
            if needle and needle in line:
                return needle, line[:800]
    return None, None


def wait_for_alert(log_path: Path, start_offset: int, needles: list[str], timeout_seconds: int) -> tuple[str | None, str | None]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        text = read_new_text(log_path, start_offset)
        matched_needle, matched_line = find_matching_line(text, needles)
        if matched_line:
            return matched_needle, matched_line
        time.sleep(2)
    return None, None


def environment_ready(args: argparse.Namespace) -> tuple[bool, Path | None]:
    service_names = args.wazuh_service or list(WAZUH_SERVICE_CANDIDATES)
    service = query_wazuh_service(service_names)
    alert_log, looks_real = resolve_wazuh_alert_log(args.wazuh_alert_log)

    alert_log_label = alert_log or "not found"
    if alert_log and not looks_real:
        alert_log_label = f"{alert_log} (local app fallback, not real Wazuh agent alerts.json)"

    print_kv("service", f"{service['name']} ({service['state']})" if service else "not found")
    print_kv("alert_log", alert_log_label)

    if platform.system().lower() != "windows":
        print("result: SKIP - this script is written for Windows Wazuh endpoints.")
        return False, alert_log

    if not args.skip_service_check:
        if not service:
            print("result: FAIL - Wazuh service was not found on this endpoint.")
            return False, alert_log
        if not service["running"]:
            print("result: FAIL - Wazuh service exists but is not running.")
            return False, alert_log

    if not alert_log:
        print("result: FAIL - Wazuh alerts.json was not found.")
        return False, None

    if not looks_real:
        print("result: FAIL - only the app fallback log was found, so this would not prove Wazuh detection.")
        return False, alert_log

    return True, alert_log


def start_process_signal(lifetime_seconds: int) -> tuple[subprocess.Popen, str]:
    marker = f"{PROCESS_MARKER_PREFIX}_{uuid4().hex[:12]}"
    command = [
        sys.executable,
        "-c",
        "import time; time.sleep(int(__import__('sys').argv[1]))",
        str(lifetime_seconds),
        marker,
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return process, marker


def run_process_detection_test(args: argparse.Namespace) -> bool:
    print_section("Wazuh Process Detection Test")
    ready, alert_log = environment_ready(args)
    if not ready or not alert_log:
        return False

    lifetime = max(args.timeout + 15, args.process_lifetime)
    start_offset = file_size_or_zero(alert_log)
    process: subprocess.Popen | None = None

    try:
        process, marker = start_process_signal(lifetime)
        needles = [marker, str(process.pid)]
        print_kv("signal", "harmless Python sleep process")
        print_kv("pid", process.pid)
        print_kv("marker", marker)
        print(f"waiting: up to {args.timeout}s for Wazuh to alert on this process...")

        matched_needle, matched_line = wait_for_alert(alert_log, start_offset, needles, args.timeout)
        if matched_line:
            print("result: PASS - Wazuh wrote a matching process alert.")
            print_kv("matched_by", matched_needle)
            print_kv("matched_alert", matched_line)
            return True

        print("result: NOT OBSERVED - no Wazuh process alert matched before timeout.")
        print("hint: process detection usually needs Sysmon process creation collection and a matching Wazuh rule.")
        return False
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def emit_ip_signal(test_ip: str, test_port: int, connect_timeout: float) -> str:
    try:
        with socket.create_connection((test_ip, test_port), timeout=connect_timeout):
            return "connection succeeded"
    except OSError as exc:
        return f"connection attempt ended: {exc}"


def run_ip_detection_test(args: argparse.Namespace) -> bool:
    print_section("Wazuh IP/Network Detection Test")
    ready, alert_log = environment_ready(args)
    if not ready or not alert_log:
        return False

    start_offset = file_size_or_zero(alert_log)
    print_kv("signal", "short TCP connection attempt")
    print_kv("destination", f"{args.test_ip}:{args.test_port}")
    emit_result = emit_ip_signal(args.test_ip, args.test_port, args.connect_timeout)
    print_kv("emit_result", emit_result)
    print(f"waiting: up to {args.timeout}s for Wazuh to alert on this destination IP...")

    matched_needle, matched_line = wait_for_alert(alert_log, start_offset, [args.test_ip], args.timeout)
    if matched_line:
        print("result: PASS - Wazuh wrote a matching network/IP alert.")
        print_kv("matched_by", matched_needle)
        print_kv("matched_alert", matched_line)
        return True

    print("result: NOT OBSERVED - no Wazuh network alert matched before timeout.")
    print("hint: IP detection usually needs Sysmon network connection collection and a matching Wazuh rule.")
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safely test whether Wazuh detects process and IP/network signals."
    )
    parser.add_argument(
        "--kind",
        choices=("process", "ip", "all"),
        default="all",
        help="Detection signal to test. Default: all",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Seconds to wait for a matching Wazuh alert. Default: 60",
    )
    parser.add_argument(
        "--wazuh-alert-log",
        default=None,
        help="Explicit Wazuh alerts.json path. Default: auto-detect common Windows agent paths.",
    )
    parser.add_argument(
        "--wazuh-service",
        action="append",
        help="Wazuh service name to query. Can be repeated. Default: common Wazuh service names.",
    )
    parser.add_argument(
        "--skip-service-check",
        action="store_true",
        help="Monitor the alert log without requiring a local Wazuh service.",
    )
    parser.add_argument(
        "--process-lifetime",
        type=int,
        default=45,
        help="Minimum lifetime for the harmless process signal. Default: 45",
    )
    parser.add_argument(
        "--test-ip",
        default=DEFAULT_TEST_IP,
        help=f"Destination IP for network detection test. Default: {DEFAULT_TEST_IP}",
    )
    parser.add_argument(
        "--test-port",
        type=int,
        default=DEFAULT_TEST_PORT,
        help=f"Destination port for network detection test. Default: {DEFAULT_TEST_PORT}",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=3.0,
        help="Seconds to wait for the TCP connection attempt. Default: 3.0",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = []

    if args.kind in {"process", "all"}:
        results.append(("process", run_process_detection_test(args)))
    if args.kind in {"ip", "all"}:
        results.append(("ip", run_ip_detection_test(args)))

    print_section("Summary")
    for name, passed in results:
        print_kv(name, "PASS" if passed else "FAIL/NOT OBSERVED")

    return 0 if results and all(passed for _, passed in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
