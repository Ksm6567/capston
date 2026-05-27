#!/usr/bin/env python3
"""Run safe detection-engine checks for the Capstone EDR project.

Default mode checks detection engines, not just UI response paths:

* yara: creates a harmless marker file and runs the local YARA rules directly.
* ip: attempts a short TCP connection to a documentation IP address and checks
  whether Wazuh alerts include that destination IP.
* process: starts a short-lived harmless Python sleep process and checks whether
  Wazuh alerts include the process marker or PID.

No malware is created or executed. The legacy app-response incident tests are
still available through --response-test when you only want to exercise the UI
buttons and backend response workflow.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_YARA_RULES_PATH = PROJECT_ROOT / "backend" / "rules" / "enhanced_rules.yar"
LOCAL_WAZUH_ALERT_LOG = PROJECT_ROOT / "logs" / "wazuh_alerts.jsonl"
YARA_SAFE_MARKER = "CAPSTONE_EDR_SAFE_YARA_TEST_INCIDENT"
WAZUH_MARKER_PREFIX = "CAPSTONE_WAZUH_ENGINE_TEST"

WAZUH_ALERT_LOG_CANDIDATES = [
    os.environ.get("WAZUH_ALERT_LOG_PATH"),
    r"C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json",
    r"C:\Program Files\ossec-agent\logs\alerts\alerts.json",
    str(LOCAL_WAZUH_ALERT_LOG),
]

WAZUH_SERVICE_CANDIDATES = ("WazuhSvc", "Wazuh", "ossec-agent")
PROCESS_MARKER_PREFIX = "CAPSTONE_WAZUH_PROCESS_DETECTION_TEST"
DEFAULT_TEST_IP = "203.0.113.10"
DEFAULT_TEST_PORT = 443
SYSMON_EVENT_LOG = "Microsoft-Windows-Sysmon/Operational"

RESPONSE_TEST_ENDPOINTS = {
    "yara": "/api/incidents/test-yara",
    "process": "/api/incidents/test-wazuh-process",
    "ip": "/api/incidents/test-wazuh-ip",
}


def print_section(title: str) -> None:
    print(f"\n=== {title} ===")


def print_kv(key: str, value: object) -> None:
    print(f"{key}: {value}")


def api_url(base_url: str, path: str) -> str:
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def request_json(
    method: str,
    url: str,
    *,
    token: str | None = None,
    payload: dict | None = None,
) -> dict:
    body = None
    headers = {}

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Session-Token"] = token

    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            text = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(text)
        except json.JSONDecodeError:
            detail = text
        raise RuntimeError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not connect to {url}: {exc}") from exc

    if not text:
        return {}
    return json.loads(text)


def login(base_url: str, username: str, password: str) -> str:
    data = request_json(
        "POST",
        api_url(base_url, "/api/auth/login"),
        payload={"username": username, "password": password},
    )
    token = data.get("token") or data.get("access_token") or data.get("session_token")
    if not token:
        raise RuntimeError("Login succeeded but no session token was returned.")
    return token


def run_response_tests(args: argparse.Namespace) -> int:
    print_section("App Response Workflow Test")
    token = login(args.base_url, args.username, args.password)
    kinds = list(RESPONSE_TEST_ENDPOINTS) if args.response_test == "all" else [args.response_test]

    for kind in kinds:
        endpoint = RESPONSE_TEST_ENDPOINTS[kind]
        result = request_json("POST", api_url(args.base_url, endpoint), token=token)
        print(f"[{kind}] {json.dumps(result, ensure_ascii=False)}")

    print("Done. Refresh the Threat Detection view in the app to see the incidents.")
    return 0


def create_yara_sample(sample_dir: Path) -> Path:
    sample_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sample_path = sample_dir / f"capstone_safe_yara_engine_test_{timestamp}.txt"
    sample_path.write_text(
        "\n".join(
            [
                "Capstone EDR safe YARA engine test file.",
                "This file is harmless and contains only a marker for a local test rule.",
                YARA_SAFE_MARKER,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return sample_path


def run_yara_engine_test(args: argparse.Namespace) -> bool:
    print_section("1. YARA Engine Test")
    rules_path = Path(args.yara_rules).resolve()
    sample_path = create_yara_sample(Path(args.sample_dir).resolve())

    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from backend.src.yara_scanner import scan_file_with_rules
    except Exception as exc:
        print_kv("status", "error")
        print_kv("reason", f"Could not import local YARA scanner: {exc}")
        return False

    result = scan_file_with_rules(str(rules_path), str(sample_path))
    matched = result.get("status") == "matched"

    print_kv("sample", sample_path)
    print_kv("rules", rules_path)
    print_kv("status", result.get("status"))
    print_kv("matches", ", ".join(result.get("matches", [])) or "-")
    if result.get("message"):
        print_kv("message", result["message"])

    if matched:
        print("result: PASS - the YARA engine matched the harmless test marker.")
    else:
        print("result: FAIL - the YARA engine did not match the harmless test marker.")
    return matched


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


def query_windows_event_log(log_name: str) -> str:
    if platform.system().lower() != "windows":
        return "not available"

    completed = run_command(["wevtutil.exe", "gl", log_name])
    if completed.returncode != 0:
        return "not found"

    enabled = "unknown"
    record_count = "unknown"
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("enabled:"):
            enabled = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("numberofrecords:"):
            record_count = stripped.split(":", 1)[1].strip()
    return f"enabled={enabled}, records={record_count}"


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


def find_matching_line(text: str, marker: str) -> str | None:
    for line in text.splitlines():
        if marker in line:
            return line[:500]
    return None


def emit_windows_event(marker: str) -> tuple[bool, str]:
    message = f"Capstone Wazuh safe detection engine test marker={marker}"
    completed = run_command(
        [
            "eventcreate.exe",
            "/L",
            "APPLICATION",
            "/T",
            "WARNING",
            "/ID",
            "1000",
            "/SO",
            "CapstoneEDRTest",
            "/D",
            message,
        ],
        timeout=15,
    )
    output = (completed.stdout or completed.stderr or "").strip()
    return completed.returncode == 0, output


def emit_process_signal(marker: str) -> tuple[bool, str]:
    command = [
        sys.executable,
        "-c",
        "import time; time.sleep(8)",
        marker,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        return False, f"failed to start harmless marker process: {exc}"
    return True, f"started harmless marker process pid={process.pid}"


def wait_for_wazuh_marker(log_path: Path, marker: str, start_offset: int, timeout_seconds: int) -> str | None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        text = read_new_text(log_path, start_offset)
        match = find_matching_line(text, marker)
        if match:
            return match
        time.sleep(2)
    return None


def find_matching_needle_line(text: str, needles: list[str]) -> tuple[str | None, str | None]:
    for line in text.splitlines():
        for needle in needles:
            if needle and needle in line:
                return needle, line[:800]
    return None, None


def wait_for_wazuh_needles(
    log_path: Path,
    needles: list[str],
    start_offset: int,
    timeout_seconds: int,
) -> tuple[str | None, str | None]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        text = read_new_text(log_path, start_offset)
        matched_needle, matched_line = find_matching_needle_line(text, needles)
        if matched_line:
            return matched_needle, matched_line
        time.sleep(2)
    return None, None


def check_wazuh_environment(args: argparse.Namespace) -> tuple[bool, Path | None]:
    service_names = args.wazuh_service or list(WAZUH_SERVICE_CANDIDATES)
    service = query_wazuh_service(service_names)
    alert_log, looks_real = resolve_wazuh_alert_log(args.wazuh_alert_log)
    alert_log_label = alert_log or "not found"
    if alert_log and not looks_real:
        alert_log_label = f"{alert_log} (local app fallback, not real Wazuh agent alerts.json)"

    print_kv("service", f"{service['name']} ({service['state']})" if service else "not found")
    print_kv("alert_log", alert_log_label)
    print_kv("sysmon_log", query_windows_event_log(SYSMON_EVENT_LOG))

    if platform.system().lower() != "windows":
        print("result: SKIP - this Wazuh test is written for Windows endpoints.")
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


def emit_ip_signal(test_ip: str, test_port: int, connect_timeout: float) -> str:
    timeout_ms = max(1, int(connect_timeout * 1000))
    ps_script = (
        "$ErrorActionPreference = 'SilentlyContinue'; "
        f"$client = [System.Net.Sockets.TcpClient]::new(); "
        f"$iar = $client.BeginConnect('{test_ip}', {test_port}, $null, $null); "
        f"if (-not $iar.AsyncWaitHandle.WaitOne({timeout_ms}, $false)) "
        "{ $client.Close(); Write-Output 'connection timed out'; exit 0 }; "
        "try { $client.EndConnect($iar); Write-Output 'connection succeeded' } "
        "catch { Write-Output ('connection attempt ended: ' + $_.Exception.Message) } "
        "finally { if ($client) { $client.Close() } }"
    )
    try:
        completed = run_command(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            timeout=int(connect_timeout) + 8,
        )
        output = (completed.stdout or completed.stderr or "").strip()
        if output:
            return f"powershell network signal: {output}"
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        with socket.create_connection((test_ip, test_port), timeout=connect_timeout):
            return "python fallback connection succeeded"
    except OSError as exc:
        return f"python fallback connection attempt ended: {exc}"


def run_ip_detection_test(args: argparse.Namespace) -> bool:
    print_section("2. IP Block Detection Test")
    ready, alert_log = check_wazuh_environment(args)
    if not ready or not alert_log:
        return False

    start_offset = file_size_or_zero(alert_log)
    print_kv("signal", "short TCP connection attempt")
    print_kv("destination", f"{args.test_ip}:{args.test_port}")
    emit_result = emit_ip_signal(args.test_ip, args.test_port, args.connect_timeout)
    print_kv("emit_result", emit_result)
    print(f"waiting: up to {args.timeout}s for Wazuh to alert on this destination IP...")

    matched_needle, matched_line = wait_for_wazuh_needles(alert_log, [args.test_ip], start_offset, args.timeout)
    if matched_line:
        print("result: PASS - Wazuh wrote a matching network/IP alert.")
        print_kv("matched_by", matched_needle)
        print_kv("matched_alert", matched_line)
        return True

    print("result: NOT OBSERVED - no Wazuh network alert matched before timeout.")
    print("hint: IP detection usually needs Sysmon network connection collection and a matching Wazuh rule.")
    return False


def start_process_detection_signal(lifetime_seconds: int) -> tuple[subprocess.Popen, str]:
    marker = f"{PROCESS_MARKER_PREFIX}_{uuid4().hex[:12]}"
    command = [
        "powershell.exe",
        "-NoProfile",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"$marker = '{marker}'; Start-Sleep -Seconds {int(lifetime_seconds)}",
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
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
    print_section("3. Process Termination Detection Test")
    ready, alert_log = check_wazuh_environment(args)
    if not ready or not alert_log:
        return False

    lifetime = max(args.timeout + 15, args.process_lifetime)
    start_offset = file_size_or_zero(alert_log)
    process: subprocess.Popen | None = None

    try:
        process, marker = start_process_detection_signal(lifetime)
        needles = [marker, str(process.pid)]
        print_kv("signal", "harmless PowerShell sleep process")
        print_kv("pid", process.pid)
        print_kv("marker", marker)
        print(f"waiting: up to {args.timeout}s for Wazuh to alert on this process...")

        matched_needle, matched_line = wait_for_wazuh_needles(alert_log, needles, start_offset, args.timeout)
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


def run_wazuh_engine_test(args: argparse.Namespace) -> bool:
    print_section("Wazuh Engine/Pipeline Test")
    service_names = args.wazuh_service or list(WAZUH_SERVICE_CANDIDATES)
    service = query_wazuh_service(service_names)
    alert_log, looks_real = resolve_wazuh_alert_log(args.wazuh_alert_log)
    alert_log_label = alert_log or "not found"
    if alert_log and not looks_real:
        alert_log_label = f"{alert_log} (local app fallback, not real Wazuh agent alerts.json)"

    print_kv("service", f"{service['name']} ({service['state']})" if service else "not found")
    print_kv("alert_log", alert_log_label)

    if platform.system().lower() != "windows":
        print("result: SKIP - this Wazuh signal test is written for Windows endpoints.")
        return False

    if not service:
        print("result: FAIL - Wazuh service was not found on this endpoint.")
        return False

    if not service["running"]:
        print("result: FAIL - Wazuh service exists but is not running.")
        return False

    if not alert_log:
        print("result: FAIL - Wazuh alerts.json was not found.")
        return False

    if not looks_real:
        print("warning: only the local app fallback log was found; that does not prove Wazuh itself is producing alerts.")

    marker = f"{WAZUH_MARKER_PREFIX}_{uuid4().hex[:12]}"
    start_offset = file_size_or_zero(alert_log)

    if args.wazuh_signal == "process":
        emitted, output = emit_process_signal(marker)
    else:
        emitted, output = emit_windows_event(marker)

    print_kv("signal", args.wazuh_signal)
    print_kv("marker", marker)
    print_kv("emit_result", output or ("ok" if emitted else "failed"))

    if not emitted:
        print("result: FAIL - could not emit the harmless Wazuh test signal.")
        return False

    print(f"waiting: up to {args.timeout}s for Wazuh to write a matching alert...")
    matching_line = wait_for_wazuh_marker(alert_log, marker, start_offset, args.timeout)
    if matching_line:
        print("result: PASS - the marker appeared in the Wazuh alerts log.")
        print_kv("matched_alert", matching_line)
        return True

    print("result: NOT OBSERVED - Wazuh did not write a matching alert before timeout.")
    print("hint: check that Wazuh is connected to a manager and collects the selected Windows event/process source.")
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safely test Capstone EDR detection engines from Python."
    )
    parser.add_argument(
        "--kind",
        choices=("menu", "yara", "ip", "process", "wazuh", "response-ip", "response-process", "all"),
        default="menu",
        help="Detection test to run. Default: interactive menu",
    )
    parser.add_argument(
        "--sample-dir",
        default=str(PROJECT_ROOT / "test_samples" / "engine_samples"),
        help="Directory where harmless YARA sample files are created.",
    )
    parser.add_argument(
        "--yara-rules",
        default=str(LOCAL_YARA_RULES_PATH),
        help="YARA rule file or directory to use for the YARA engine test.",
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
        "--wazuh-signal",
        choices=("eventlog", "process"),
        default="eventlog",
        help="Harmless signal to emit for Wazuh. Default: eventlog",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Seconds to wait for a Wazuh alert. Default: 60",
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
        help=f"Destination IP for IP block detection test. Default: {DEFAULT_TEST_IP}",
    )
    parser.add_argument(
        "--test-port",
        type=int,
        default=DEFAULT_TEST_PORT,
        help=f"Destination port for IP block detection test. Default: {DEFAULT_TEST_PORT}",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=3.0,
        help="Seconds to wait for the TCP connection attempt. Default: 3.0",
    )
    parser.add_argument(
        "--response-test",
        choices=("yara", "process", "ip", "all"),
        help="Legacy app workflow test: create safe backend incidents instead of testing engines.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Running backend URL for --response-test. Default: http://127.0.0.1:8000",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Login username for --response-test. Default: admin",
    )
    parser.add_argument(
        "--password",
        default="admin1234",
        help="Login password for --response-test. Default: admin1234",
    )
    return parser.parse_args()


def prompt_menu() -> str:
    print("\n=== Capstone Safe Detection Tests ===")
    print("1. YARA 테스트")
    print("2. IP 차단 탐지 테스트 (Wazuh 필요)")
    print("3. 프로세스 종료 탐지 테스트 (Wazuh 필요)")
    print("4. IP 차단 대응 테스트 (앱/방화벽)")
    print("5. 프로세스 종료 대응 테스트 (앱/taskkill)")
    print("0. 종료")

    choices = {
        "1": "yara",
        "2": "ip",
        "3": "process",
        "4": "response_ip",
        "5": "response_process",
        "0": "exit",
    }
    while True:
        selected = input("선택하세요 (1/2/3/4/5): ").strip()
        if selected in choices:
            return choices[selected]
        print("잘못된 입력입니다. 1, 2, 3, 4, 5 중에서 선택하세요.")


def run_selected_tests(args: argparse.Namespace) -> list[tuple[str, bool]]:
    selected_kind = prompt_menu() if args.kind == "menu" else args.kind
    if selected_kind == "exit":
        return []

    results = []
    if selected_kind in {"yara", "all"}:
        results.append(("yara", run_yara_engine_test(args)))
    if selected_kind in {"ip", "all"}:
        results.append(("ip", run_ip_detection_test(args)))
    if selected_kind in {"process", "all"}:
        results.append(("process", run_process_detection_test(args)))
    if selected_kind == "wazuh":
        results.append(("wazuh", run_wazuh_engine_test(args)))
    if selected_kind in {"response_ip", "response-ip"}:
        args.response_test = "ip"
        results.append(("response_ip", run_response_tests(args) == 0))
    if selected_kind in {"response_process", "response-process"}:
        args.response_test = "process"
        results.append(("response_process", run_response_tests(args) == 0))
    return results


def main() -> int:
    args = parse_args()

    try:
        if args.response_test:
            return run_response_tests(args)

        results = run_selected_tests(args)
        if not results:
            print("Done.")
            return 0

        print_section("Summary")
        for name, passed in results:
            print_kv(name, "PASS" if passed else "FAIL/NOT OBSERVED")

        return 0 if results and all(passed for _, passed in results) else 2
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
