import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from uuid import uuid4

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
PROJECT_PACKAGE_ROOT = BASE_DIR.parent
if str(PROJECT_PACKAGE_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_PACKAGE_ROOT))

try:
    from backend.runtime_paths import app_root, bundle_root
    from backend.src.database import (
        authenticate_user,
        create_session,
        create_user,
        delete_logs_for_user_on_date,
        delete_logs_for_user,
        delete_session,
        get_db_log_content,
        get_log_dates_for_user,
        get_session,
        is_db_enabled,
        is_admin_username,
        init_db,
        list_usernames,
        save_log,
    )
    from backend.src.behavior_monitor import BehaviorMonitor
    from backend.src.wazuh_monitor import WazuhMonitor
    from backend.src.yara_scanner import YaraScanner, scan_file_with_rules
except ModuleNotFoundError:
    from runtime_paths import app_root, bundle_root
    from src.database import (
        authenticate_user,
        create_session,
        create_user,
        delete_logs_for_user_on_date,
        delete_logs_for_user,
        delete_session,
        get_db_log_content,
        get_log_dates_for_user,
        get_session,
        is_db_enabled,
        is_admin_username,
        init_db,
        list_usernames,
        save_log,
    )
    from src.behavior_monitor import BehaviorMonitor
    from src.wazuh_monitor import WazuhMonitor
    from src.yara_scanner import YaraScanner, scan_file_with_rules

PROJECT_ROOT = app_root()
BUNDLE_ROOT = bundle_root()
LOCAL_RULES_PATH = os.getenv(
    "YARA_LOCAL_RULES_PATH",
    str(BUNDLE_ROOT / "backend" / "rules" / "enhanced_rules.yar"),
)
EXTERNAL_RULES_PATH = os.getenv(
    "YARA_EXTERNAL_RULES_PATH",
    os.getenv("YARA_RULES_PATH", str(BUNDLE_ROOT / "backend" / "rules" / "external" / "elastic")),
)
YARA_RULE_SOURCE_LABELS = {
    "local": "local-critical",
    "external": "external-extended",
}
LOCAL_WAZUH_ALERT_LOG = str(PROJECT_ROOT / "logs" / "wazuh_alerts.jsonl")
LOCAL_WAZUH_ALERT_LOG_ALT = str(PROJECT_ROOT / "logs" / "wazuh_alert.jsonl")
DEFAULT_WAZUH_ALERT_LOG = os.getenv("WAZUH_ALERT_LOG_PATH", LOCAL_WAZUH_ALERT_LOG)
BEHAVIOR_RULE_REFERENCE_PATH = BUNDLE_ROOT / "backend" / "rules" / "wazuh" / "official" / "rules" / "0595-win-sysmon_rules.xml"
SYSMON_DOWNLOAD_URL = "https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_EVENT_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
SYSMON_INSTALL_ROOT = Path(os.getenv("CAPSTONE_SYSMON_INSTALL_ROOT", str(PROJECT_ROOT / "tools" / "sysmon"))).expanduser()
SYSMON_CONFIG_PATH = BUNDLE_ROOT / "backend" / "rules" / "sysmon" / "capstone_sysmon_config.xml"
WAZUH_MANAGER_INSTALL_URL = "https://documentation.wazuh.com/current/installation-guide/wazuh-server/index.html"
WAZUH_WINDOWS_AGENT_INSTALL_URL = "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html"
WAZUH_MANAGER_INSTALL_SCRIPT = PROJECT_ROOT / "scripts" / "install_wazuh_manager_cli.ps1"
WAZUH_ALERTS_BRIDGE_SCRIPT = PROJECT_ROOT / "scripts" / "bridge_wazuh_alerts_to_local.ps1"
WAZUH_WSL_SETUP_SCRIPT = PROJECT_ROOT / "scripts" / "setup_wazuh_manager_wsl.ps1"
WAZUH_WSL_ALERTS_BRIDGE_SCRIPT = PROJECT_ROOT / "scripts" / "bridge_wazuh_alerts_from_wsl.ps1"
INCIDENTS_PATH = PROJECT_ROOT / "data" / "incidents.json"
QUARANTINE_ROOT = PROJECT_ROOT / "quarantine"
WAZUH_ALERT_LOG_CANDIDATES = [
    path for path in [
        os.getenv("WAZUH_ALERT_LOG_PATH"),
        r"C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json",
        r"C:\Program Files\ossec-agent\logs\alerts\alerts.json",
        LOCAL_WAZUH_ALERT_LOG,
        LOCAL_WAZUH_ALERT_LOG_ALT,
    ]
    if path
]
FRONTEND_DIR = BUNDLE_ROOT / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    init_db()
    load_incidents_snapshot()
    yield


app = FastAPI(title="EDR API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

wazuh_thread = None
wazuh_bridge_process = None
yara_thread = None
yara_scan_thread = None
connected_websockets = []
loop = None
selected_wazuh_alert_log = None
WAZUH_SETUP_LOCK = Lock()
WAZUH_SETUP_JOB = {
    "running": False,
    "status": "idle",
    "message": "",
    "started_at": None,
    "finished_at": None,
    "host": None,
    "log": [],
    "returncode": None,
}
LOG_SOURCES = {"wazuh", "yara", "response"}
INCIDENTS = []
INCIDENTS_LOCK = Lock()
MAX_INCIDENTS = 100
SUSPICIOUS_FILE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jse", ".hta", ".jar", ".lnk", ".docm", ".xlsm", ".pptm",
}
HIGH_RISK_GROUP_KEYWORDS = {
    "malware", "ransomware", "trojan", "persistence", "rootkit", "powershell",
    "sysmon", "defender", "evasion", "suspicious_command", "shell_burst",
}
SKIPPED_DIR_NAMES = {
    "$recycle.bin",
    "system volume information",
}


def require_auth(x_session_token: str | None = Header(default=None, alias="X-Session-Token")):
    if not is_db_enabled():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database is unavailable.")
    if not x_session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required.")
    session = get_session(x_session_token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid.")
    return session


def resolve_log_username(current_user: dict, requested_username: str | None) -> str:
    username = current_user["username"]
    if not requested_username or requested_username == username:
        return username
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    return requested_username


def build_directory_entry(path_str: str, parent_path: str | None = None):
    normalized = os.path.normpath(path_str)
    drive = os.path.splitdrive(normalized)[0] + "\\"

    if normalized == drive:
        label = normalized
        depth = 0
    else:
        relative_path = os.path.relpath(normalized, drive)
        depth = relative_path.count(os.sep) + 1
        label = os.path.basename(normalized) or relative_path

    return {
        "label": label,
        "path": normalized,
        "depth": depth,
        "drive": drive,
        "parent_path": parent_path,
    }


def get_root_scan_directories():
    entries = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            entries.append(build_directory_entry(drive))
    return entries


def get_child_scan_directories(parent_path: str):
    normalized_parent = os.path.normpath(parent_path)
    children = []

    if not os.path.isdir(normalized_parent):
        return children

    try:
        for child in sorted(Path(normalized_parent).iterdir(), key=lambda item: item.name.lower()):
            if not child.is_dir():
                continue

            lowered_name = child.name.lower()
            if lowered_name in SKIPPED_DIR_NAMES:
                continue

            children.append(build_directory_entry(str(child), normalized_parent))
    except OSError:
        return []

    return children


def choose_scan_directory_dialog():
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Folder picker is unavailable: {exc}") from exc

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        selected_path = filedialog.askdirectory(
            title="심층 스캔 폴더 선택",
            mustexist=True,
        )
    finally:
        root.destroy()

    if not selected_path:
        return None
    return os.path.normpath(selected_path)


def get_default_yara_monitor_paths():
    configured = os.getenv("YARA_MONITOR_PATHS", "")
    if configured.strip():
        paths = [
            os.path.normpath(path.strip())
            for path in configured.split(os.pathsep)
            if path.strip() and os.path.exists(os.path.normpath(path.strip()))
        ]
        if paths:
            return paths

    home = Path.home()
    candidates = [
        home / "Desktop",
        home / "Downloads",
        home / "Documents",
        PROJECT_ROOT,
    ]
    paths = []
    for candidate in candidates:
        try:
            path = os.path.normpath(str(candidate))
            if os.path.exists(path) and path not in paths:
                paths.append(path)
        except OSError:
            continue
    return paths


def resolve_wazuh_alert_log():
    if selected_wazuh_alert_log and os.path.isfile(selected_wazuh_alert_log):
        return os.path.normpath(selected_wazuh_alert_log)

    local_candidates = {os.path.normcase(os.path.normpath(path)) for path in [LOCAL_WAZUH_ALERT_LOG, LOCAL_WAZUH_ALERT_LOG_ALT]}
    existing_local = []
    for candidate in WAZUH_ALERT_LOG_CANDIDATES:
        normalized = os.path.normpath(candidate)
        if os.path.isfile(normalized):
            if os.path.normcase(normalized) in local_candidates:
                existing_local.append(normalized)
                continue
            return normalized

    for local_path in existing_local:
        if has_wazuh_alert_entries(local_path):
            return local_path
    if existing_local:
        return existing_local[0]

    fallback = os.path.normpath(DEFAULT_WAZUH_ALERT_LOG or LOCAL_WAZUH_ALERT_LOG)
    os.makedirs(os.path.dirname(fallback), exist_ok=True)
    Path(fallback).touch(exist_ok=True)
    return fallback


def is_local_wazuh_fallback_path(path: str | None):
    if not path:
        return False
    try:
        resolved = Path(path).resolve()
        return resolved in {Path(LOCAL_WAZUH_ALERT_LOG).resolve(), Path(LOCAL_WAZUH_ALERT_LOG_ALT).resolve()}
    except (OSError, RuntimeError, ValueError):
        normalized = os.path.normcase(os.path.normpath(path))
        return normalized in {
            os.path.normcase(os.path.normpath(LOCAL_WAZUH_ALERT_LOG)),
            os.path.normcase(os.path.normpath(LOCAL_WAZUH_ALERT_LOG_ALT)),
        }


def has_wazuh_alert_entries(path: str | None):
    if not path or not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            for line in file_handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict) and (
                    isinstance(payload.get("rule"), dict)
                    or isinstance(payload.get("agent"), dict)
                    or payload.get("timestamp")
                ):
                    return True
    except OSError:
        return False
    return False


def validate_wazuh_alert_log(path: str):
    normalized = os.path.normpath(path)
    if not os.path.isfile(normalized):
        raise HTTPException(status_code=400, detail="Selected Wazuh alert log file does not exist.")
    if os.path.getsize(normalized) == 0:
        return normalized

    checked = 0
    with open(normalized, "r", encoding="utf-8", errors="replace") as file_handle:
        for line in file_handle:
            stripped = line.strip()
            if not stripped:
                continue
            checked += 1
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail=f"Selected file is not JSONL Wazuh alerts format: {exc}") from exc
            if not isinstance(payload, dict):
                raise HTTPException(status_code=400, detail="Selected file contains a non-object JSON alert line.")
            if isinstance(payload.get("rule"), dict) or isinstance(payload.get("agent"), dict) or payload.get("timestamp"):
                return normalized
            if checked >= 20:
                break

    raise HTTPException(
        status_code=400,
        detail="Selected file does not look like Wazuh alerts.json. Expected JSON lines with rule, agent, or timestamp fields.",
    )


def choose_wazuh_alert_log_dialog():
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"File picker is unavailable: {exc}") from exc

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        selected_path = filedialog.askopenfilename(
            title="Wazuh alerts.json 또는 JSONL 파일 선택",
            filetypes=[
                ("Wazuh alert logs", "*.json *.jsonl *.log"),
                ("All files", "*.*"),
            ],
        )
    finally:
        root.destroy()

    if not selected_path:
        return None
    return validate_wazuh_alert_log(selected_path)


def allow_wazuh_alert_log_bridge():
    bridge_flags = [
        os.getenv("WAZUH_ALLOW_ALERT_LOG_BRIDGE", ""),
    ]
    return any(flag.strip().lower() in {"1", "true", "yes", "on"} for flag in bridge_flags)


def get_wazuh_windows_agent_state():
    service_found = False
    service_running = False
    if os.name == "nt":
        for service_name in ("WazuhSvc", "Wazuh", "ossec-agent"):
            try:
                completed = subprocess.run(
                    ["sc.exe", "query", service_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if completed.returncode != 0:
                continue
            service_found = True
            service_running = "RUNNING" in (completed.stdout or "").upper()
            break

    install_paths = [
        r"C:\Program Files (x86)\ossec-agent",
        r"C:\Program Files\ossec-agent",
    ]
    install_path = next((path for path in install_paths if os.path.isdir(path)), None)
    return {
        "service_found": service_found,
        "service_running": service_running,
        "install_path": install_path,
    }


def get_wazuh_runtime_state():
    log_path = resolve_wazuh_alert_log()
    env_log_path = os.getenv("WAZUH_ALERT_LOG_PATH")
    bridge_log_path = is_local_wazuh_fallback_path(log_path)
    local_has_alerts = has_wazuh_alert_entries(log_path)
    cli_bridge_ready = bool(bridge_log_path and (local_has_alerts or allow_wazuh_alert_log_bridge()))
    real_alert_log = bool(
        log_path
        and os.path.isfile(log_path)
        and not bridge_log_path
    )
    configured_manager_log = bool(env_log_path and os.path.isfile(os.path.normpath(env_log_path)))
    agent_state = get_wazuh_windows_agent_state()
    ready = real_alert_log or configured_manager_log or cli_bridge_ready
    return {
        "ready": ready,
        "reason": None if ready else "missing_wazuh_manager",
        "log_path": log_path,
        "real_alert_log": real_alert_log,
        "configured_manager_log": configured_manager_log,
        "bridge_log_path": bridge_log_path,
        "cli_bridge_ready": cli_bridge_ready,
        "local_has_alerts": local_has_alerts,
        "allow_alert_log_bridge": allow_wazuh_alert_log_bridge(),
        "agent": agent_state,
        "manager_install_url": WAZUH_MANAGER_INSTALL_URL,
        "windows_agent_install_url": WAZUH_WINDOWS_AGENT_INSTALL_URL,
        "connector_script": str(PROJECT_ROOT / "scripts" / "connect_wazuh_windows_agent.ps1"),
        "manager_install_script": str(WAZUH_MANAGER_INSTALL_SCRIPT),
        "alerts_bridge_script": str(WAZUH_ALERTS_BRIDGE_SCRIPT),
    }


def sanitize_setup_text(value: str | None, *, default: str = ""):
    return (value or default).strip()


def validate_setup_host(host: str):
    host = sanitize_setup_text(host)
    if not host:
        raise HTTPException(status_code=400, detail="Linux Manager host/IP is required.")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", host):
        raise HTTPException(status_code=400, detail="Host/IP contains unsupported characters.")
    return host


def validate_setup_user(username: str):
    username = sanitize_setup_text(username)
    if username and not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", username):
        raise HTTPException(status_code=400, detail="SSH username contains unsupported characters.")
    return username


def validate_setup_port(port_value):
    try:
        port = int(port_value or 22)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="SSH port must be a number.") from exc
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="SSH port must be between 1 and 65535.")
    return port


def validate_wsl_distro(distro: str | None):
    distro = sanitize_setup_text(distro, default="Ubuntu")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", distro):
        raise HTTPException(status_code=400, detail="WSL distro name contains unsupported characters.")
    return distro


def update_wazuh_setup_job(**updates):
    with WAZUH_SETUP_LOCK:
        WAZUH_SETUP_JOB.update(updates)
        return dict(WAZUH_SETUP_JOB)


def append_wazuh_setup_log(message: str):
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {message}"
    with WAZUH_SETUP_LOCK:
        WAZUH_SETUP_JOB["log"].append(line)
        WAZUH_SETUP_JOB["log"] = WAZUH_SETUP_JOB["log"][-200:]
    return line


def get_wazuh_setup_job_snapshot():
    with WAZUH_SETUP_LOCK:
        snapshot = dict(WAZUH_SETUP_JOB)
        snapshot["log"] = list(WAZUH_SETUP_JOB["log"])
        return snapshot


def run_subprocess_for_setup(command: list[str], cwd: str | os.PathLike | None = None):
    append_wazuh_setup_log("Running: " + " ".join(command))
    process = subprocess.Popen(
        command,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert process.stdout is not None
    for output_line in process.stdout:
        stripped = output_line.strip()
        if stripped:
            append_wazuh_setup_log(stripped)
    return process.wait()


def launch_visible_setup_window(command: list[str]):
    append_wazuh_setup_log("Launching visible setup window: " + " ".join(command))
    creationflags = subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0
    return subprocess.Popen(
        command,
        cwd=str(PROJECT_ROOT),
        creationflags=creationflags,
    )


def start_wazuh_alerts_bridge_process(host: str, user: str, port: int):
    global wazuh_bridge_process
    if wazuh_bridge_process and wazuh_bridge_process.poll() is None:
        append_wazuh_setup_log("Wazuh alerts bridge is already running.")
        return

    os.environ["WAZUH_ALERT_LOG_PATH"] = LOCAL_WAZUH_ALERT_LOG
    os.environ["WAZUH_ALLOW_ALERT_LOG_BRIDGE"] = "1"
    Path(LOCAL_WAZUH_ALERT_LOG).parent.mkdir(parents=True, exist_ok=True)
    Path(LOCAL_WAZUH_ALERT_LOG).touch(exist_ok=True)

    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(WAZUH_ALERTS_BRIDGE_SCRIPT),
        "-HostName",
        host,
        "-Port",
        str(port),
    ]
    if user:
        command.extend(["-User", user])

    append_wazuh_setup_log("Starting alerts bridge process.")
    wazuh_bridge_process = subprocess.Popen(
        command,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_wazuh_monitor_from_runtime(username: str):
    global wazuh_thread
    if wazuh_thread and wazuh_thread.is_alive():
        return True

    broadcast_log("wazuh", "Starting local behavior detection with Sysmon/Wazuh ruleset references.", username)
    wazuh_thread = BehaviorMonitor(
        callback=lambda event: handle_wazuh_event({
            **event,
            "username": event.get("username") or username,
        }),
    )
    wazuh_thread.start()
    return True


def wazuh_manager_setup_worker(payload: dict, username: str):
    host = payload["host"]
    user = payload.get("user", "")
    port = payload.get("port", 22)
    try:
        update_wazuh_setup_job(status="installing_manager", message="Installing Wazuh Manager through the official CLI helper.")
        command = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(WAZUH_MANAGER_INSTALL_SCRIPT),
            "-HostName",
            host,
            "-Port",
            str(port),
            "-InstallCapstoneRules",
            "-ConnectWindowsAgent",
        ]
        if user:
            command.extend(["-User", user])
        if payload.get("agent_manager_address"):
            command.extend(["-AgentManagerAddress", payload["agent_manager_address"]])

        returncode = run_subprocess_for_setup(command, PROJECT_ROOT)
        update_wazuh_setup_job(returncode=returncode)
        if returncode != 0:
            update_wazuh_setup_job(
                running=False,
                status="failed",
                message=f"Wazuh Manager setup failed with exit code {returncode}.",
                finished_at=datetime.now().isoformat(timespec="seconds"),
            )
            broadcast_log("wazuh", f"Wazuh Manager setup failed with exit code {returncode}.", username)
            return

        update_wazuh_setup_job(status="starting_bridge", message="Starting Wazuh alerts bridge.")
        start_wazuh_alerts_bridge_process(host, user, port)
        started_monitor = start_wazuh_monitor_from_runtime(username)
        update_wazuh_setup_job(
            running=False,
            status="ready" if started_monitor else "bridge_started",
            message="Wazuh Manager setup finished. Wazuh monitoring is running." if started_monitor else "Wazuh Manager setup finished. Alerts bridge started; press Wazuh start again.",
            finished_at=datetime.now().isoformat(timespec="seconds"),
        )
        broadcast_log("wazuh", "Wazuh Manager setup finished. Alerts bridge is starting.", username)
    except Exception as exc:
        append_wazuh_setup_log(f"ERROR: {exc}")
        update_wazuh_setup_job(
            running=False,
            status="failed",
            message=str(exc),
            finished_at=datetime.now().isoformat(timespec="seconds"),
        )
        broadcast_log("wazuh", f"Wazuh Manager setup failed: {exc}", username)


def sanitize_log_source(source: str):
    normalized = (source or "").strip().lower()
    return normalized if normalized in LOG_SOURCES else None


def sanitize_username_for_path(username: str | None):
    if not username:
        return "system"
    return "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in username)


def build_log_file_path(source: str, date_str: str, username: str | None):
    owner_dir = os.path.join(PROJECT_ROOT, "logs", sanitize_username_for_path(username))
    return os.path.join(owner_dir, f"{source}_alerts_{date_str}.log")


def build_user_log_dir(username: str):
    return os.path.join(PROJECT_ROOT, "logs", sanitize_username_for_path(username))


def is_valid_log_date(date_str: str):
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def should_persist_log(source: str, message: str):
    normalized_source = sanitize_log_source(source)
    normalized_message = (message or "").strip().lower()

    if not normalized_source or not normalized_message:
        return False

    if normalized_source == "wazuh":
        return "[wazuh alert]" in normalized_message or "[behavior detect]" in normalized_message
    if normalized_source == "yara":
        return "[yara detect]" in normalized_message or "[yara verify]" in normalized_message
    if normalized_source == "response":
        return "[response]" in normalized_message

    return False


def list_file_log_dates_by_source(username: str):
    log_dir = os.path.join(PROJECT_ROOT, "logs", sanitize_username_for_path(username))
    result = {source: [] for source in sorted(LOG_SOURCES)}

    if not os.path.exists(log_dir):
        return result

    for source in LOG_SOURCES:
        prefix = f"{source}_alerts_"
        files = [
            file_name for file_name in os.listdir(log_dir)
            if file_name.startswith(prefix) and file_name.endswith(".log")
        ]
        dates = [file_name.removeprefix(prefix).removesuffix(".log") for file_name in files]
        dates.sort(reverse=True)
        result[source] = dates

    return result


def merge_log_dates(username: str):
    combined = list_file_log_dates_by_source(username)
    db_dates = get_log_dates_for_user(LOG_SOURCES, username)

    for source in combined:
        for date_str in db_dates.get(source, []):
            if date_str not in combined[source]:
                combined[source].append(date_str)
        combined[source].sort(reverse=True)

    return combined


def count_file_log_lines(source: str, date_str: str, username: str):
    file_path = build_log_file_path(source, date_str, username)
    if not os.path.isfile(file_path):
        return 0
    try:
        with open(file_path, "r", encoding="utf-8") as file_handle:
            return sum(1 for line in file_handle if line.strip())
    except OSError:
        return 0


def build_log_entries(username: str):
    dates_by_source = merge_log_dates(username)
    entries = []
    for source in sorted(dates_by_source):
        for date_str in dates_by_source[source]:
            file_count = count_file_log_lines(source, date_str, username)
            db_content = get_db_log_content(source, date_str, username)
            db_count = len([line for line in db_content.splitlines() if line.strip()])
            entries.append({
                "source": source,
                "date": date_str,
                "count": file_count + db_count,
            })
    entries.sort(key=lambda item: (item["date"], item["source"]), reverse=True)
    return entries


def write_to_file_log(source: str, message: str, username: str | None):
    normalized_source = sanitize_log_source(source)
    if not normalized_source or not should_persist_log(normalized_source, message):
        return

    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")

    log_dir = os.path.join(PROJECT_ROOT, "logs", sanitize_username_for_path(username))
    os.makedirs(log_dir, exist_ok=True)
    with open(build_log_file_path(normalized_source, date_str, username), "a", encoding="utf-8") as file_handle:
        file_handle.write(f"[{time_str}] {message}\n")


def broadcast_log(source: str, message: str, username: str | None = None, persist: bool = True, details: dict | None = None):
    if persist and should_persist_log(source, message):
        if username:
            write_to_file_log(source, message, username)
        save_log(source, message, username)

    payload = {
        "source": source,
        "message": message,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "username": username,
    }
    if details:
        payload["details"] = details

    if loop and loop.is_running():
        for client in connected_websockets.copy():
            visible_to = client["username"]
            if username is not None and visible_to != username:
                continue
            try:
                asyncio.run_coroutine_threadsafe(client["websocket"].send_json(payload), loop)
            except Exception:
                pass


def recommend_response(level: int, file_path: str | None, yara_result: dict | None = None, alert_fields: dict | None = None):
    actions = []
    alert_fields = alert_fields or {}

    if yara_result and yara_result.get("status") == "matched":
        actions.append("Isolate the affected endpoint from the network")
        actions.append("Quarantine the matched file")
        actions.append("Preserve the host and behavior logs for triage")
    elif level >= 10:
        actions.append("Prioritize analyst triage and isolate the host if behavior persists")
        actions.append("Inspect the originating process tree and scheduled tasks")
    elif level >= 6:
        actions.append("Review the behavior alert and validate the endpoint context")
        actions.append("Collect the suspicious file and related logs for sandbox analysis")
    else:
        actions.append("Record the event and continue monitoring for repeated behavior")

    if file_path:
        actions.append(f"Track remediation status for file: {file_path}")
    if alert_fields.get("process_id"):
        actions.append(f"Stop the suspicious process if still running: PID {alert_fields['process_id']}")
    if alert_fields.get("destination_ip"):
        actions.append(f"Block outbound traffic to destination IP: {alert_fields['destination_ip']}")

    return actions


def calculate_risk(level: int, file_path: str | None, groups: list[str], yara_result: dict | None = None):
    score = min(100, max(0, level * 6))
    lowered_groups = [group.lower() for group in groups]

    if any(keyword in group for group in lowered_groups for keyword in HIGH_RISK_GROUP_KEYWORDS):
        score += 15

    if file_path:
        extension = os.path.splitext(file_path)[1].lower()
        if extension in SUSPICIOUS_FILE_EXTENSIONS:
            score += 10
    else:
        score = max(0, score - 5)

    if yara_result:
        if yara_result.get("status") == "matched":
            score += 35
        elif yara_result.get("status") == "clean":
            score = max(0, score - 10)
        elif yara_result.get("status") == "missing":
            score += 5

    score = max(0, min(100, score))

    if score >= 80:
        risk_label = "critical"
    elif score >= 60:
        risk_label = "high"
    elif score >= 35:
        risk_label = "medium"
    else:
        risk_label = "low"

    return score, risk_label


def today_incident_date():
    return datetime.now().date().isoformat()


def incident_date(incident: dict):
    created_at = str(incident.get("created_at") or "").strip()
    if not created_at:
        return None
    return created_at.split("T", 1)[0].split(" ", 1)[0]


def is_today_incident(incident: dict):
    return incident_date(incident) == today_incident_date()


def prune_stale_incidents():
    removed = False
    with INCIDENTS_LOCK:
        today_items = [incident for incident in INCIDENTS if is_today_incident(incident)]
        if len(today_items) != len(INCIDENTS):
            INCIDENTS.clear()
            INCIDENTS.extend(today_items)
            removed = True
    if removed:
        persist_incidents_snapshot()


def persist_incidents_snapshot():
    try:
        INCIDENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with INCIDENTS_LOCK:
            snapshot = [incident.copy() for incident in INCIDENTS[:MAX_INCIDENTS]]
        temp_path = INCIDENTS_PATH.with_suffix(".json.tmp")
        with open(temp_path, "w", encoding="utf-8") as file_handle:
            json.dump(snapshot, file_handle, ensure_ascii=False, indent=2)
        os.replace(temp_path, INCIDENTS_PATH)
    except Exception as exc:
        print(f"[INCIDENT WARNING] Failed to persist incidents: {exc}")


def load_incidents_snapshot():
    if not INCIDENTS_PATH.exists():
        return
    try:
        with open(INCIDENTS_PATH, "r", encoding="utf-8") as file_handle:
            snapshot = json.load(file_handle)
        if not isinstance(snapshot, list):
            return
        loaded = [
            incident
            for incident in snapshot
            if isinstance(incident, dict) and incident.get("id")
        ][:MAX_INCIDENTS]
        with INCIDENTS_LOCK:
            INCIDENTS.clear()
            INCIDENTS.extend(loaded)
        prune_stale_incidents()
    except Exception as exc:
        print(f"[INCIDENT WARNING] Failed to load incidents: {exc}")


def store_incident(incident: dict):
    prune_stale_incidents()
    with INCIDENTS_LOCK:
        INCIDENTS.insert(0, incident)
        del INCIDENTS[MAX_INCIDENTS:]
    persist_incidents_snapshot()
    broadcast_log(
        "response",
        f"[Incident] Created {incident.get('risk_label', 'unknown').upper()} incident: "
        f"{incident.get('rule_description') or incident.get('wazuh_message') or incident.get('id')}",
        incident.get("owner_username"),
        persist=False,
        details={"kind": "incident_created", "incident_id": incident.get("id")},
    )


def list_incidents(username: str):
    prune_stale_incidents()
    with INCIDENTS_LOCK:
        return [
            incident.copy()
            for incident in INCIDENTS
            if incident.get("owner_username") == username
        ]


def get_incident(incident_id: str, username: str):
    with INCIDENTS_LOCK:
        for incident in INCIDENTS:
            if incident["id"] == incident_id and incident.get("owner_username") == username:
                return incident
    return None


def parse_process_id(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def calculate_file_sha256(file_path: str):
    digest = hashlib.sha256()
    with open(file_path, "rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_quarantine_name(name: str):
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in name) or "quarantined_file"


def is_quarantine_storage_path(file_path: str | None):
    if not file_path:
        return False
    try:
        path = Path(file_path).resolve()
        quarantine_root = QUARANTINE_ROOT.resolve()
        return path == quarantine_root or quarantine_root in path.parents
    except (OSError, RuntimeError, ValueError):
        normalized = os.path.normpath(file_path).lower()
        return f"{os.sep}quarantine{os.sep}" in normalized


def create_safe_yara_test_file(username: str):
    sample_dir = PROJECT_ROOT / "test_samples" / sanitize_username_for_path(username)
    os.makedirs(sample_dir, exist_ok=True)
    file_path = sample_dir / f"capstone_safe_yara_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    content = "\n".join([
        "Capstone EDR safe YARA workflow test file.",
        "This file is harmless and contains only a marker for the local test rule.",
        "CAPSTONE_EDR_SAFE_YARA_TEST_INCIDENT",
        "",
    ])
    with open(file_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(content)
    return str(file_path)


def start_safe_process_test_target():
    command = [
        sys.executable,
        "-c",
        "import time; time.sleep(300)",
    ]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.Popen(command, creationflags=creation_flags)


def quarantine_incident_file(incident: dict, username: str):
    file_path = incident.get("file_path")
    if not file_path:
        return "error", "Quarantine failed: no file path was available.", "error"
    if not os.path.isfile(file_path):
        return "error", f"Quarantine failed: target file does not exist. {file_path}", "error"

    try:
        quarantine_dir = PROJECT_ROOT / "quarantine" / sanitize_username_for_path(username)
        os.makedirs(quarantine_dir, exist_ok=True)

        original_name = sanitize_quarantine_name(os.path.basename(file_path))
        target_path = quarantine_dir / f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{incident['id'][:8]}_{original_name}"
        file_hash = calculate_file_sha256(file_path)
        shutil.move(file_path, target_path)

        metadata = {
            "incident_id": incident["id"],
            "original_path": file_path,
            "quarantine_path": str(target_path),
            "sha256": file_hash,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "username": username,
        }
        metadata_path = quarantine_dir / "manifest.jsonl"
        with open(metadata_path, "a", encoding="utf-8") as file_handle:
            file_handle.write(f"{json.dumps(metadata, ensure_ascii=False)}\n")
    except Exception as exc:
        return "error", f"Quarantine failed for {file_path}: {exc}", "error"

    incident["file_path"] = str(target_path)
    incident["file_exists"] = True
    incident["quarantine_original_path"] = file_path
    incident["quarantine_path"] = str(target_path)
    incident["file_sha256"] = file_hash
    return "quarantined", f"Quarantine success: file moved to {target_path}", "success"


def shell_message(completed: subprocess.CompletedProcess):
    return (completed.stderr or completed.stdout or "").strip()


def is_permission_error(message: str, returncode: int | None = None):
    normalized = (message or "").lower()
    permission_markers = [
        "access is denied",
        "permission",
        "administrator",
        "requires elevation",
        "elevated",
        "run as administrator",
        "requested operation requires elevation",
        "740",
        "\uc561\uc138\uc2a4\uac00 \uac70\ubd80",
        "\uc811\uadfc\uc774 \uac70\ubd80",
        "\uad8c\ud55c",
        "\uad00\ub9ac\uc790",
        "\uc2b9\uaca9",
    ]
    return returncode == 740 or any(marker in normalized for marker in permission_markers)


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def read_elevated_result(result_path: Path):
    if not result_path.exists():
        return None
    try:
        with open(result_path, "r", encoding="utf-8-sig") as file_handle:
            payload = json.load(file_handle)
        return payload if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def query_sysmon_status():
    if os.name != "nt":
        return {
            "installed": False,
            "running": False,
            "service_name": None,
            "event_log": None,
            "reason": "Sysmon is only supported by this installer on Windows.",
        }

    service_name = None
    running = False
    for candidate in ("Sysmon64", "Sysmon"):
        try:
            completed = subprocess.run(
                ["sc.exe", "query", candidate],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode != 0:
            continue
        service_name = candidate
        output = f"{completed.stdout}\n{completed.stderr}"
        running = "RUNNING" in output.upper()
        break

    try:
        event_log_check = subprocess.run(
            ["wevtutil.exe", "gl", SYSMON_EVENT_LOG_NAME],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        event_log_available = event_log_check.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        event_log_available = False
    event_log_readable = False
    if event_log_available:
        try:
            event_query_check = subprocess.run(
                ["wevtutil.exe", "qe", SYSMON_EVENT_LOG_NAME, "/rd:true", "/c:1", "/f:xml"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            query_output = f"{event_query_check.stdout}\n{event_query_check.stderr}".lower()
            event_log_readable = event_query_check.returncode == 0 or "no events" in query_output
        except (OSError, subprocess.TimeoutExpired):
            event_log_readable = False
    return {
        "installed": bool(service_name or event_log_available),
        "running": running,
        "service_name": service_name,
        "event_log": SYSMON_EVENT_LOG_NAME if event_log_available else None,
        "event_log_readable": event_log_readable,
        "config_path": str(SYSMON_CONFIG_PATH),
        "download_url": SYSMON_DOWNLOAD_URL,
    }


def build_elevated_sysmon_install_script():
    return f"""
$ErrorActionPreference = 'Stop'
$ResultPath = __RESULT_PATH__
$InstallRoot = {ps_quote(str(SYSMON_INSTALL_ROOT))}
$ZipPath = Join-Path $InstallRoot 'Sysmon.zip'
$LogPath = Join-Path $InstallRoot 'sysmon_install.log'
$DownloadUrl = {ps_quote(SYSMON_DOWNLOAD_URL)}
$ConfigPath = {ps_quote(str(SYSMON_CONFIG_PATH))}
$InstallConfigPath = Join-Path $InstallRoot 'capstone_sysmon_config.xml'
$EventLogName = {ps_quote(SYSMON_EVENT_LOG_NAME)}
function Invoke-CapstoneNative {{
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )
    $StdoutPath = Join-Path $InstallRoot ("native_stdout_" + [guid]::NewGuid().ToString("N") + ".log")
    $StderrPath = Join-Path $InstallRoot ("native_stderr_" + [guid]::NewGuid().ToString("N") + ".log")
    try {{
        $Process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $InstallRoot -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
        $StdoutText = if (Test-Path -LiteralPath $StdoutPath) {{ Get-Content -LiteralPath $StdoutPath -Raw -Encoding Unicode -ErrorAction SilentlyContinue }} else {{ "" }}
        if (-not $StdoutText -and (Test-Path -LiteralPath $StdoutPath)) {{
            $StdoutText = Get-Content -LiteralPath $StdoutPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        }}
        $StderrText = if (Test-Path -LiteralPath $StderrPath) {{ Get-Content -LiteralPath $StderrPath -Raw -Encoding Unicode -ErrorAction SilentlyContinue }} else {{ "" }}
        if (-not $StderrText -and (Test-Path -LiteralPath $StderrPath)) {{
            $StderrText = Get-Content -LiteralPath $StderrPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        }}
        $OutputText = "$StdoutText`n$StderrText".Trim()
        $ExitCode = $Process.ExitCode
        return [ordered]@{{
            output = $OutputText
            exit_code = $ExitCode
        }}
    }} finally {{
        Remove-Item -LiteralPath $StdoutPath,$StderrPath -Force -ErrorAction SilentlyContinue
    }}
}}
try {{
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    "[$(Get-Date -Format s)] Starting Sysmon installation" | Set-Content -LiteralPath $LogPath -Encoding UTF8
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    "[$(Get-Date -Format s)] Downloading $DownloadUrl" | Add-Content -LiteralPath $LogPath -Encoding UTF8
    try {{
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
    }} catch {{
        "[$(Get-Date -Format s)] Invoke-WebRequest failed: $($_.Exception.Message)" | Add-Content -LiteralPath $LogPath -Encoding UTF8
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($DownloadUrl, $ZipPath)
    }}
    "[$(Get-Date -Format s)] Extracting $ZipPath" | Add-Content -LiteralPath $LogPath -Encoding UTF8
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $InstallRoot -Force

    $Exe = Join-Path $InstallRoot 'Sysmon64.exe'
    if (-not [Environment]::Is64BitOperatingSystem -or -not (Test-Path -LiteralPath $Exe)) {{
        $Exe = Join-Path $InstallRoot 'Sysmon.exe'
    }}
    if (-not (Test-Path -LiteralPath $Exe)) {{
        throw "Sysmon executable was not found after extraction."
    }}
    if (-not (Test-Path -LiteralPath $ConfigPath)) {{
        throw "Sysmon config file is missing: $ConfigPath"
    }}
    Copy-Item -LiteralPath $ConfigPath -Destination $InstallConfigPath -Force
    Unblock-File -LiteralPath $Exe -ErrorAction SilentlyContinue
    Unblock-File -LiteralPath $InstallConfigPath -ErrorAction SilentlyContinue

    $EventLogService = Get-Service -Name 'EventLog' -ErrorAction SilentlyContinue
    if ($EventLogService -and $EventLogService.Status -ne 'Running') {{
        Start-Service -Name 'EventLog' -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }}

    $Existing = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $Existing) {{
        "[$(Get-Date -Format s)] No Sysmon service found. Cleaning stale Sysmon install leftovers if present." | Add-Content -LiteralPath $LogPath -Encoding UTF8
        $StalePaths = @(
            (Join-Path $env:WINDIR 'Sysmon64.exe'),
            (Join-Path $env:WINDIR 'Sysmon.exe'),
            (Join-Path $env:WINDIR 'Sysmon64a.exe'),
            (Join-Path $env:WINDIR 'System32\\drivers\\SysmonDrv.sys')
        )
        foreach ($StalePath in $StalePaths) {{
            if (Test-Path -LiteralPath $StalePath) {{
                try {{
                    attrib.exe -R -S -H $StalePath 2>$null
                    Remove-Item -LiteralPath $StalePath -Force -ErrorAction Stop
                    "[$(Get-Date -Format s)] Removed stale Sysmon path: $StalePath" | Add-Content -LiteralPath $LogPath -Encoding UTF8
                }} catch {{
                    "[$(Get-Date -Format s)] Could not remove stale Sysmon path ${{StalePath}}: $($_.Exception.Message)" | Add-Content -LiteralPath $LogPath -Encoding UTF8
                }}
            }}
        }}
    }}
    if ($Existing) {{
        "[$(Get-Date -Format s)] Updating existing Sysmon config with $InstallConfigPath" | Add-Content -LiteralPath $LogPath -Encoding UTF8
        $Run = Invoke-CapstoneNative -FilePath $Exe -Arguments @('-accepteula','-c',$InstallConfigPath)
        $Output = $Run.output
        $Code = $Run.exit_code
    }} else {{
        "[$(Get-Date -Format s)] Installing Sysmon with $InstallConfigPath" | Add-Content -LiteralPath $LogPath -Encoding UTF8
        $Run = Invoke-CapstoneNative -FilePath $Exe -Arguments @('-accepteula','-i',$InstallConfigPath)
        $Output = $Run.output
        $Code = $Run.exit_code
        if ($Code -ne 0) {{
            "[$(Get-Date -Format s)] Config install failed with code $Code. Retrying same install command once." | Add-Content -LiteralPath $LogPath -Encoding UTF8
            if ($Output) {{ $Output | Add-Content -LiteralPath $LogPath -Encoding UTF8 }}
            Start-Sleep -Seconds 2
            $RetryRun = Invoke-CapstoneNative -FilePath $Exe -Arguments @('-accepteula','-i',$InstallConfigPath)
            $RetryOutput = $RetryRun.output
            $Output = "$Output`n$RetryOutput".Trim()
            $Code = $RetryRun.exit_code
        }}
        if ($Code -ne 0) {{
            "[$(Get-Date -Format s)] Second install attempt failed with code $Code. Trying forced Sysmon cleanup then install." | Add-Content -LiteralPath $LogPath -Encoding UTF8
            if ($Output) {{ $Output | Add-Content -LiteralPath $LogPath -Encoding UTF8 }}
            $CleanupRun = Invoke-CapstoneNative -FilePath $Exe -Arguments @('-u','force')
            $CleanupOutput = $CleanupRun.output
            if ($CleanupOutput) {{ $CleanupOutput | Add-Content -LiteralPath $LogPath -Encoding UTF8 }}
            Start-Sleep -Seconds 2
            $FinalRun = Invoke-CapstoneNative -FilePath $Exe -Arguments @('-accepteula','-i',$InstallConfigPath)
            $FinalOutput = $FinalRun.output
            $Output = "$Output`n$CleanupOutput`n$FinalOutput".Trim()
            $Code = $FinalRun.exit_code
        }}
    }}
    "[$(Get-Date -Format s)] Sysmon command exit code: $Code" | Add-Content -LiteralPath $LogPath -Encoding UTF8
    if ($Output) {{
        "[$(Get-Date -Format s)] Sysmon output:" | Add-Content -LiteralPath $LogPath -Encoding UTF8
        $Output | Add-Content -LiteralPath $LogPath -Encoding UTF8
    }}

    $Service = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Service -and $Service.Status -ne 'Running') {{
        Start-Service -Name $Service.Name -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $Service = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
    }}

    $LogOk = $false
    try {{
        wevtutil.exe gl $EventLogName | Out-Null
        $LogOk = $true
    }} catch {{
        $LogOk = $false
    }}
    if ($LogOk) {{
        $ChannelAccess = 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;BU)'
        $ChannelOutput = (& wevtutil.exe sl $EventLogName /e:true /ca:$ChannelAccess 2>&1 | Out-String).Trim()
        if ($ChannelOutput) {{
            "[$(Get-Date -Format s)] Sysmon channel access update: $ChannelOutput" | Add-Content -LiteralPath $LogPath -Encoding UTF8
        }} else {{
            "[$(Get-Date -Format s)] Sysmon channel access updated for local app read access." | Add-Content -LiteralPath $LogPath -Encoding UTF8
        }}
    }}

    if ($Code -eq 0 -and $Service) {{
        $Payload = [ordered]@{{
            status = 'installed'
            result_type = 'success'
            result_message = "Sysmon installed/configured successfully. Service: $($Service.Name), Status: $($Service.Status)."
            service_name = $Service.Name
            service_status = "$($Service.Status)"
            event_log = $EventLogName
            event_log_available = $LogOk
            install_root = $InstallRoot
            log_path = $LogPath
            output = $Output
        }}
    }} else {{
        $Payload = [ordered]@{{
            status = 'error'
            result_type = 'error'
            result_message = "Sysmon install/configuration failed. See install log: $LogPath"
            output = $Output
            exit_code = $Code
            log_path = $LogPath
        }}
    }}
}} catch {{
    try {{
        "[$(Get-Date -Format s)] ERROR: $($_.Exception.Message)" | Add-Content -LiteralPath $LogPath -Encoding UTF8
        ($_ | Out-String) | Add-Content -LiteralPath $LogPath -Encoding UTF8
    }} catch {{ }}
    $Payload = [ordered]@{{
        status = 'error'
        result_type = 'error'
        result_message = "Sysmon install failed: $($_.Exception.Message)"
        log_path = $LogPath
    }}
}}
try {{
    $Payload | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}} catch {{
    "[$(Get-Date -Format s)] Failed to write result JSON: $($_.Exception.Message)" | Add-Content -LiteralPath $LogPath -Encoding UTF8
}}
if ($Payload['status'] -eq 'installed') {{ exit 0 }} else {{ exit 1 }}
"""


def read_sysmon_install_log_tail(max_lines: int = 80):
    log_path = SYSMON_INSTALL_ROOT / "sysmon_install.log"
    if not log_path.exists():
        return {
            "status": "missing",
            "log_path": str(log_path),
            "content": "",
        }
    try:
        with open(log_path, "r", encoding="utf-8-sig", errors="replace") as file_handle:
            lines = file_handle.read().splitlines()
    except OSError as exc:
        return {
            "status": "error",
            "log_path": str(log_path),
            "content": str(exc),
        }
    return {
        "status": "ok",
        "log_path": str(log_path),
        "content": "\n".join(lines[-max_lines:]),
    }


def run_elevated_powershell(script_body: str, timeout_seconds: int = 120):
    if os.name != "nt":
        return {
            "status": "error",
            "result_message": "Elevation failed: administrator approval is only available on Windows.",
            "result_type": "error",
        }

    with tempfile.TemporaryDirectory(prefix="capstone_edr_elevated_") as temp_dir:
        temp_path = Path(temp_dir)
        script_path = temp_path / "action.ps1"
        result_path = temp_path / "result.json"
        script_path.write_text(script_body.replace("__RESULT_PATH__", ps_quote(str(result_path))), encoding="utf-8")

        launch_command = (
            "$ErrorActionPreference = 'Stop'; "
            "try { "
            "$p = Start-Process -FilePath 'powershell.exe' "
            f"-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',{ps_quote(str(script_path))}) "
            "-Verb RunAs -Wait -PassThru; "
            "if ($null -eq $p.ExitCode) { exit 0 } else { exit $p.ExitCode } "
            "} catch { Write-Error $_.Exception.Message; exit 1223 }"
        )

        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", launch_command],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "result_message": "Elevation timed out: administrator approval window was not completed.",
                "result_type": "error",
            }
        except OSError as exc:
            return {
                "status": "error",
                "result_message": f"Elevation failed: {exc}",
                "result_type": "error",
            }

        payload = read_elevated_result(result_path)
        if payload:
            return payload

        message = shell_message(completed)
        fallback_log = SYSMON_INSTALL_ROOT / "sysmon_install.log"
        log_tail = ""
        if fallback_log.exists():
            try:
                with open(fallback_log, "r", encoding="utf-8-sig", errors="replace") as file_handle:
                    lines = file_handle.read().splitlines()
                log_tail = "\n".join(lines[-12:])
            except OSError:
                log_tail = ""
        canceled = completed.returncode == 1223 or "canceled" in message.lower() or "cancelled" in message.lower() or "\ucde8\uc18c" in message
        if canceled:
            message = "Administrator approval was canceled."
        elif not message and log_tail:
            message = f"Action failed. See log: {fallback_log}"
        elif log_tail and completed.returncode not in (0, None):
            message = f"{message or 'Action failed.'} See log: {fallback_log}"
        return {
            "status": "error",
            "result_message": f"Elevation failed: {message or completed.returncode}",
            "result_type": "error",
            "log_path": str(fallback_log) if fallback_log.exists() else None,
        }


def build_elevated_terminate_script(pid: int):
    return f"""
$ErrorActionPreference = 'Stop'
$ResultPath = __RESULT_PATH__
$PidValue = {pid}
try {{
    $Output = (& taskkill.exe /PID $PidValue /T /F 2>&1 | Out-String).Trim()
    $Code = $LASTEXITCODE
    if ($Code -eq 0) {{
        $Payload = [ordered]@{{
            status = 'terminated'
            result_message = "Terminate success: administrator approved and process tree for PID $PidValue was stopped."
            result_type = 'success'
            process_terminated = $true
        }}
    }} else {{
        $Payload = [ordered]@{{
            status = 'error'
            result_message = "Terminate failed for PID $PidValue after administrator approval: $Output"
            result_type = 'error'
        }}
    }}
}} catch {{
    $Payload = [ordered]@{{
        status = 'error'
        result_message = "Terminate failed for PID $PidValue after administrator approval: $($_.Exception.Message)"
        result_type = 'error'
    }}
}}
$Payload | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8
if ($Payload.status -eq 'terminated') {{ exit 0 }} else {{ exit 1 }}
"""


def build_elevated_block_ip_script(destination_ip: str, rule_name: str):
    return f"""
$ErrorActionPreference = 'Stop'
$ResultPath = __RESULT_PATH__
$DestinationIp = {ps_quote(destination_ip)}
$RuleName = {ps_quote(rule_name)}
try {{
    $Output = (& netsh.exe advfirewall firewall add rule name="$RuleName" dir=out action=block remoteip="$DestinationIp" 2>&1 | Out-String).Trim()
    $Code = $LASTEXITCODE
    if ($Code -eq 0) {{
        $Payload = [ordered]@{{
            status = 'blocked'
            result_message = "Block IP success: administrator approved and outbound traffic to $DestinationIp is blocked."
            result_type = 'success'
            blocked_ip = $DestinationIp
            firewall_rule = $RuleName
        }}
    }} else {{
        $Payload = [ordered]@{{
            status = 'error'
            result_message = "Block IP failed for $DestinationIp after administrator approval: $Output"
            result_type = 'error'
        }}
    }}
}} catch {{
    $Payload = [ordered]@{{
        status = 'error'
        result_message = "Block IP failed for $DestinationIp after administrator approval: $($_.Exception.Message)"
        result_type = 'error'
    }}
}}
$Payload | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8
if ($Payload.status -eq 'blocked') {{ exit 0 }} else {{ exit 1 }}
"""


def terminate_incident_process(incident: dict, allow_elevation: bool = False):
    pid = parse_process_id(incident.get("process_id"))
    if not pid:
        return "error", "Terminate failed: no process ID was captured from the behavior alert.", "error"
    if pid <= 4 or pid in {os.getpid(), os.getppid()}:
        return "error", f"Terminate refused: protected process ID {pid}.", "error"

    try:
        completed = subprocess.run(
            ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "error", f"Terminate failed for PID {pid}: {exc}", "error"

    if completed.returncode != 0:
        message = shell_message(completed)
        if allow_elevation and is_permission_error(message, completed.returncode):
            elevated = run_elevated_powershell(build_elevated_terminate_script(pid))
            if elevated.get("status") == "terminated":
                incident["process_terminated"] = True
                incident["elevated_response"] = True
                return "terminated", elevated.get("result_message", f"Terminate success: process tree for PID {pid} was stopped."), "success"
            return "error", elevated.get("result_message", f"Terminate failed for PID {pid}: administrator approval was canceled or failed."), elevated.get("result_type", "error")
        if is_permission_error(message, completed.returncode):
            message = f"{message or completed.returncode} Administrator approval is required; run the manual response button to approve elevation."
        return "error", f"Terminate failed for PID {pid}: {message or completed.returncode}", "error"

    incident["process_terminated"] = True
    return "terminated", f"Terminate success: process tree for PID {pid} was stopped.", "success"


def block_incident_ip(incident: dict, allow_elevation: bool = False):
    destination_ip = (incident.get("destination_ip") or "").strip()
    if not destination_ip:
        return "error", "Block IP failed: no destination IP was captured from the behavior alert.", "error"

    try:
        ipaddress.ip_address(destination_ip)
    except ValueError:
        return "error", f"Block IP failed: destination is not a valid IP address. {destination_ip}", "error"

    rule_name = f"CapstoneEDR Block {destination_ip} {incident['id'][:8]}"
    try:
        completed = subprocess.run(
            [
                "netsh.exe", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block", f"remoteip={destination_ip}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "error", f"Block IP failed for {destination_ip}: {exc}", "error"

    if completed.returncode != 0:
        message = shell_message(completed)
        if allow_elevation and is_permission_error(message, completed.returncode):
            elevated = run_elevated_powershell(build_elevated_block_ip_script(destination_ip, rule_name))
            if elevated.get("status") == "blocked":
                incident["blocked_ip"] = elevated.get("blocked_ip", destination_ip)
                incident["firewall_rule"] = elevated.get("firewall_rule", rule_name)
                incident["elevated_response"] = True
                return "blocked", elevated.get("result_message", f"Block IP success: outbound traffic to {destination_ip} is blocked."), "success"
            return "error", elevated.get("result_message", f"Block IP failed for {destination_ip}: administrator approval was canceled or failed."), elevated.get("result_type", "error")
        if is_permission_error(message, completed.returncode):
            message = f"{message or completed.returncode} Administrator approval is required; run the manual response button to approve elevation."
        return "error", f"Block IP failed for {destination_ip}: {message or completed.returncode}", "error"

    incident["blocked_ip"] = destination_ip
    incident["firewall_rule"] = rule_name
    return "blocked", f"Block IP success: outbound traffic to {destination_ip} is blocked.", "success"


def get_external_rules_path():
    return EXTERNAL_RULES_PATH if os.path.exists(EXTERNAL_RULES_PATH) else None


def select_yara_rules_path(prefer_external: bool):
    if prefer_external:
        external_rules_path = get_external_rules_path()
        if external_rules_path:
            return external_rules_path, "external"
    return LOCAL_RULES_PATH, "local"


def run_yara_verification(file_path: str, username: str | None = None, prefer_external: bool = True):
    rules_path, rule_source = select_yara_rules_path(prefer_external)
    rule_label = YARA_RULE_SOURCE_LABELS[rule_source]
    if prefer_external and rule_source != "external":
        broadcast_log("yara", "[Yara VERIFY] External extended rules are unavailable; falling back to local critical rules.", username)

    broadcast_log("yara", f"[Yara VERIFY] Starting {rule_label} verification for: {file_path}", username)
    result = scan_file_with_rules(rules_path, file_path)
    result["rule_source"] = rule_label
    result["rules_path"] = rules_path

    if result["status"] == "matched":
        match_names = ", ".join(result["matches"])
        broadcast_log("yara", f"[Yara DETECT] {rule_label} verification hit for {file_path} | Rules Matched: {match_names}", username)
    elif result["status"] == "clean":
        broadcast_log("yara", f"[Yara VERIFY] No {rule_label} Yara rules matched for: {file_path}", username)
    else:
        broadcast_log("yara", f"[Yara VERIFY] {result['message']}", username)

    return result


def process_wazuh_alert(event: dict):
    message = event.get("message", "Received behavior event.")
    level = event.get("level", 0)
    file_path = event.get("file_path")
    groups = event.get("groups", [])
    mitre = event.get("mitre", {})
    alert_fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
    username = event.get("username")

    broadcast_log("wazuh", message, username)

    yara_result = None
    if file_path:
        yara_result = run_yara_verification(file_path, username)
    else:
        broadcast_log("yara", "[Yara VERIFY] Skipped file verification because the behavior event did not include a file path.", username)

    risk_score, risk_label = calculate_risk(level, file_path, groups, yara_result)
    response_actions = recommend_response(level, file_path, yara_result, alert_fields)
    if yara_result and yara_result.get("status") == "matched" and file_path:
        decision_hint = "quarantine"
    elif alert_fields.get("process_id") and risk_score >= 70:
        decision_hint = "terminate_process"
    elif alert_fields.get("destination_ip") and risk_score >= 70:
        decision_hint = "block_ip"
    else:
        decision_hint = "keep"
    response_message = (
        f"Risk {risk_label.upper()} ({risk_score}) | Suggested decision: {decision_hint.upper()} | "
        + " ; ".join(response_actions)
    )
    broadcast_log("response", f"[Response] {response_message}", username)

    incident = {
        "id": str(uuid4()),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "status": "pending",
        "decision": None,
        "decision_note": "Awaiting analyst decision.",
        "wazuh_level": level,
        "wazuh_message": message,
        "file_path": file_path,
        "file_exists": bool(file_path and os.path.isfile(file_path)),
        "groups": groups,
        "mitre": mitre,
        "rule_id": alert_fields.get("rule_id"),
        "rule_description": alert_fields.get("rule_description"),
        "agent_name": alert_fields.get("agent_name"),
        "agent_id": alert_fields.get("agent_id"),
        "process_id": alert_fields.get("process_id"),
        "process_guid": alert_fields.get("process_guid"),
        "process_image": alert_fields.get("process_image"),
        "parent_process_image": alert_fields.get("parent_process_image"),
        "command_line": alert_fields.get("command_line"),
        "destination_ip": alert_fields.get("destination_ip"),
        "destination_hostname": alert_fields.get("destination_hostname"),
        "destination_port": alert_fields.get("destination_port"),
        "registry_key": alert_fields.get("registry_key"),
        "registry_value": alert_fields.get("registry_value"),
        "yara_status": yara_result.get("status") if yara_result else "skipped",
        "yara_matches": yara_result.get("matches", []) if yara_result else [],
        "risk_score": risk_score,
        "risk_label": risk_label,
        "recommended_actions": response_actions,
        "suggested_decision": decision_hint,
        "owner_username": username,
    }
    store_incident(incident)


def process_yara_monitor_message(message: str, username: str, details: dict | None = None):
    if "[Yara DETECT]" not in message:
        return

    file_path = None
    matches = []
    file_hash = None
    file_size = None
    if "File:" in message:
        file_part = message.split("File:", 1)[1].split("|", 1)[0].strip()
        if file_part:
            file_path = os.path.normpath(file_part)
    if "Rules Matched:" in message:
        match_part = message.split("Rules Matched:", 1)[1].strip()
        matches = [item.strip() for item in match_part.split(",") if item.strip()]

    if details:
        file_path = details.get("file_path") or file_path
        file_hash = details.get("sha256")
        file_size = details.get("file_size")
        detail_matches = details.get("matches") if isinstance(details.get("matches"), list) else []
        detail_rule_names = [
            item.get("rule")
            for item in detail_matches
            if isinstance(item, dict) and item.get("rule")
        ]
        if detail_rule_names:
            matches = detail_rule_names

    if is_quarantine_storage_path(file_path):
        broadcast_log("yara", f"[Yara VERIFY] Ignored quarantined file detection: {file_path}", username)
        return

    response_actions = recommend_response(
        level=10,
        file_path=file_path,
        yara_result={"status": "matched", "matches": matches},
    )
    response_message = (
        "Risk CRITICAL (95) | Suggested decision: QUARANTINE | "
        + " ; ".join(response_actions)
    )
    broadcast_log("response", f"[Response] {response_message}", username)

    incident = {
        "id": str(uuid4()),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "status": "pending",
        "decision": None,
        "decision_note": "Awaiting analyst decision.",
        "wazuh_level": 0,
        "wazuh_message": "YARA standalone monitor detection.",
        "file_path": file_path,
        "file_exists": bool(file_path and os.path.isfile(file_path)),
        "file_sha256": file_hash,
        "file_size": file_size,
        "groups": ["yara", "malware"],
        "mitre": {},
        "rule_id": None,
        "rule_description": matches[0] if matches else "YARA rule matched",
        "agent_name": "local-yara-monitor",
        "agent_id": None,
        "process_id": None,
        "process_guid": None,
        "process_image": None,
        "parent_process_image": None,
        "command_line": None,
        "destination_ip": None,
        "destination_hostname": None,
        "destination_port": None,
        "registry_key": None,
        "registry_value": None,
        "yara_status": "matched",
        "yara_matches": matches,
        "yara_match_details": details.get("matches", []) if details else [],
        "risk_score": 95,
        "risk_label": "critical",
        "recommended_actions": response_actions,
        "suggested_decision": "quarantine",
        "owner_username": username,
    }
    store_incident(incident)


def handle_yara_monitor_message(message: str, username: str, details: dict | None = None):
    broadcast_log("yara", message, username, details=details)
    process_yara_monitor_message(message, username, details)


def handle_wazuh_event(event: dict):
    if event.get("kind") == "alert":
        Thread(target=process_wazuh_alert, args=(event,), daemon=True).start()
        return

    broadcast_log("wazuh", event.get("message", "Received behavior monitor status update."), event.get("username"))


@app.post("/api/auth/register")
def register_user(payload: dict):
    username = (payload or {}).get("username", "").strip()
    password = (payload or {}).get("password", "")
    success, message = create_user(username, password)
    return {"status": "created" if success else "error", "message": message}


@app.post("/api/auth/login")
def login(payload: dict):
    username = (payload or {}).get("username", "").strip()
    password = (payload or {}).get("password", "")
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    token, expires_at = create_session(user.username)
    if not token:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create a session.")

    broadcast_log("response", f"[Response] User {user.username} signed in.", user.username)
    return {
        "token": token,
        "user": {"username": user.username, "is_admin": is_admin_username(user.username)},
        "expires_at": expires_at.isoformat() if expires_at else None,
    }


@app.get("/api/auth/me")
def who_am_i(current_user: dict = Depends(require_auth)):
    return {"user": {"username": current_user["username"], "is_admin": current_user.get("is_admin", False)}}


@app.get("/api/users")
def get_users(current_user: dict = Depends(require_auth)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    return {"users": list_usernames()}


@app.post("/api/auth/logout")
def logout(current_user: dict = Depends(require_auth), x_session_token: str | None = Header(default=None, alias="X-Session-Token")):
    delete_session(x_session_token or "")
    broadcast_log("response", f"[Response] User {current_user['username']} signed out.", current_user["username"])
    return {"status": "signed out"}


@app.get("/api/incidents")
def get_incidents(current_user: dict = Depends(require_auth)):
    return {"incidents": list_incidents(current_user["username"])}


@app.post("/api/incidents/test-yara")
def create_test_yara_incident(current_user: dict = Depends(require_auth)):
    username = current_user["username"]
    file_path = create_safe_yara_test_file(username)
    result = scan_file_with_rules(LOCAL_RULES_PATH, file_path)
    if result.get("status") != "matched":
        return {
            "status": "not matched",
            "file_path": file_path,
            "rules_path": LOCAL_RULES_PATH,
            "message": result.get("message") or "The safe YARA test rule did not match.",
            "matches": result.get("matches", []),
        }

    stat = os.stat(file_path)
    matches = result.get("matches", [])
    details = {
        "kind": "yara_match",
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
        "file_size": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        "sha256": calculate_file_sha256(file_path),
        "rules_path": LOCAL_RULES_PATH,
        "matches": [
            {
                "rule": rule_name,
                "namespace": None,
                "tags": [],
                "meta": {
                    "description": "Safe Capstone EDR test marker for incident workflow validation",
                    "severity": "critical",
                    "safe_test": "true",
                },
            }
            for rule_name in matches
        ],
    }
    message = f"[Yara DETECT] File: {file_path} | Rules Matched: {', '.join(matches)}"
    handle_yara_monitor_message(message, username, details)
    return {
        "status": "created",
        "file_path": file_path,
        "matches": matches,
        "message": "Safe YARA test incident created.",
    }


@app.post("/api/incidents/test-wazuh-process")
def create_test_wazuh_process_incident(current_user: dict = Depends(require_auth)):
    username = current_user["username"]
    try:
        process = start_safe_process_test_target()
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start safe test process: {exc}") from exc

    process_image = sys.executable
    event = {
        "kind": "alert",
        "message": (
            "[Behavior DETECT] Safe process termination test: repeated cmd-style "
            f"process behavior simulated for PID {process.pid}."
        ),
        "level": 12,
        "file_path": None,
        "groups": ["sysmon", "process_creation", "suspicious_process"],
        "mitre": {"technique": ["T1059"], "tactic": ["Execution"]},
        "username": username,
        "fields": {
            "rule_id": "999901",
            "rule_description": "Safe Capstone behavior process termination test",
            "agent_name": "local-test-agent",
            "agent_id": "000",
            "process_id": str(process.pid),
            "process_guid": f"capstone-test-{process.pid}",
            "process_image": process_image,
            "parent_process_image": os.path.basename(sys.executable),
            "command_line": f"{process_image} -c \"import time; time.sleep(300)\"",
        },
    }
    process_wazuh_alert(event)
    return {
        "status": "created",
        "process_id": process.pid,
        "process_image": process_image,
        "message": "Safe behavior incident created. Use the process terminate button to stop it.",
    }


@app.post("/api/incidents/test-wazuh-ip")
def create_test_wazuh_ip_incident(current_user: dict = Depends(require_auth)):
    username = current_user["username"]
    destination_ip = "203.0.113.10"
    event = {
        "kind": "alert",
        "message": (
            "[Behavior DETECT] Safe IP block test: suspicious outbound "
            f"connection simulated to {destination_ip}."
        ),
        "level": 12,
        "file_path": None,
        "groups": ["sysmon", "network_connection", "suspicious_network"],
        "mitre": {"technique": ["T1071"], "tactic": ["Command and Control"]},
        "username": username,
        "fields": {
            "rule_id": "999902",
            "rule_description": "Safe Capstone behavior IP block test",
            "agent_name": "local-test-agent",
            "agent_id": "000",
            "destination_ip": destination_ip,
            "destination_hostname": "reserved-test.example",
            "destination_port": "443",
        },
    }
    process_wazuh_alert(event)
    return {
        "status": "created",
        "destination_ip": destination_ip,
        "message": "Safe behavior IP block incident created. Use the IP block button to add the firewall rule.",
    }


@app.post("/api/incidents/{incident_id}/decision")
def decide_incident(incident_id: str, payload: dict, current_user: dict = Depends(require_auth)):
    incident = get_incident(incident_id, current_user["username"])
    if not incident:
        return {
            "status": "not found",
            "result_message": "Incident not found.",
            "result_type": "error",
        }

    action = (payload or {}).get("action", "").strip().lower()
    if action not in {"quarantine", "terminate_process", "block_ip", "keep"}:
        return {
            "status": "invalid action",
            "result_message": "Invalid incident action.",
            "result_type": "error",
        }

    allow_elevation = bool((payload or {}).get("allow_elevation"))

    if action == "quarantine":
        status_value, result_message, result_type = quarantine_incident_file(incident, current_user["username"])
    elif action == "terminate_process":
        status_value, result_message, result_type = terminate_incident_process(incident, allow_elevation)
    elif action == "block_ip":
        status_value, result_message, result_type = block_incident_ip(incident, allow_elevation)
    else:
        status_value, result_message, result_type = "kept", "Incident marked as kept for monitoring.", "info"

    if status_value != "error":
        incident["status"] = status_value
        incident["decision"] = action
    else:
        incident["last_failed_action"] = action
    incident["decision_note"] = result_message
    persist_incidents_snapshot()
    broadcast_log("response", f"[Response] {result_message}", current_user["username"])
    return {
        "status": status_value,
        "incident": incident.copy(),
        "result_message": result_message,
        "result_type": result_type,
    }


@app.post("/api/incidents/{incident_id}/open-folder")
def open_incident_folder(incident_id: str, current_user: dict = Depends(require_auth)):
    incident = get_incident(incident_id, current_user["username"])
    if not incident:
        return {"status": "not found"}

    file_path = incident.get("file_path")
    if not file_path:
        return {"status": "missing path"}

    folder_path = file_path if os.path.isdir(file_path) else os.path.dirname(file_path)
    if not folder_path or not os.path.isdir(folder_path):
        return {"status": "missing folder"}

    try:
        os.startfile(folder_path)
    except OSError as exc:
        return {"status": "error", "message": str(exc)}

    return {"status": "opened", "folder": folder_path}


@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    session = get_session(token)
    if not session:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    client = {"websocket": websocket, "username": session["username"]}
    connected_websockets.append(client)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if client in connected_websockets:
            connected_websockets.remove(client)
    except Exception:
        if client in connected_websockets:
            connected_websockets.remove(client)


@app.get("/api/status")
def get_status(current_user: dict = Depends(require_auth)):
    wazuh_active = bool(wazuh_thread and wazuh_thread.is_alive())
    behavior_runtime = (
        wazuh_thread.get_status()
        if wazuh_thread and hasattr(wazuh_thread, "get_status")
        else {
            "ready": True,
            "mode": "stopped",
            "event_log": None,
            "rules_reference": str(BEHAVIOR_RULE_REFERENCE_PATH),
        }
    )
    wazuh_log_path = behavior_runtime.get("event_log") or behavior_runtime.get("rules_reference") or ""
    yara_target_paths = yara_thread.get_scan_roots() if yara_thread else get_default_yara_monitor_paths()
    return {
        "wazuh_running": wazuh_active,
        "wazuh_mode": behavior_runtime.get("mode") if wazuh_active else "stopped",
        "wazuh_ready": True,
        "wazuh_runtime": behavior_runtime,
        "yara_running": yara_thread.is_alive() if yara_thread else False,
        "yara_scan_running": yara_scan_thread.is_alive() if yara_scan_thread else False,
        "username": current_user["username"],
        "wazuh_log_path": wazuh_log_path,
        "wazuh_log_candidates": [],
        "yara_target_paths": yara_target_paths,
        "yara_scan_target_paths": yara_scan_thread.get_scan_roots() if yara_scan_thread else [],
        "yara_rules_path": yara_thread.rules_path if yara_thread else LOCAL_RULES_PATH,
        "yara_scan_rules_path": yara_scan_thread.rules_path if yara_scan_thread else EXTERNAL_RULES_PATH,
    }


@app.get("/api/behavior/sysmon-status")
def get_sysmon_install_status(current_user: dict = Depends(require_auth)):
    return query_sysmon_status()


@app.get("/api/behavior/sysmon-install-log")
def get_sysmon_install_log(current_user: dict = Depends(require_auth)):
    return read_sysmon_install_log_tail()


@app.post("/api/behavior/install-sysmon")
def install_sysmon(current_user: dict = Depends(require_auth)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    if os.name != "nt":
        raise HTTPException(status_code=400, detail="Sysmon installation is only supported on Windows.")

    before = query_sysmon_status()
    if (
        before.get("installed")
        and before.get("running")
        and before.get("event_log")
        and before.get("event_log_readable")
    ):
        return {
            "status": "already installed",
            "result_type": "success",
            "result_message": "Sysmon is already installed and running.",
            "sysmon": before,
        }

    result = run_elevated_powershell(build_elevated_sysmon_install_script(), timeout_seconds=240)
    after = query_sysmon_status()
    result["sysmon"] = after
    if after.get("installed") and after.get("running") and after.get("event_log"):
        result.update({
            "status": "installed",
            "result_type": "success" if after.get("event_log_readable") else "warn",
            "result_message": (
                f"Sysmon is installed and running. Service: {after.get('service_name')}."
                if after.get("event_log_readable")
                else f"Sysmon is running, but the app still cannot read the Sysmon event log. See install log: {SYSMON_INSTALL_ROOT / 'sysmon_install.log'}"
            ),
        })
    if result.get("status") == "installed":
        broadcast_log("wazuh", "Sysmon installed/configured. Behavior detection can use Sysmon events.", current_user["username"])
    return result


@app.post("/api/wazuh/start")
def start_wazuh(current_user: dict = Depends(require_auth)):
    global wazuh_thread
    if wazuh_thread and wazuh_thread.is_alive():
        runtime = wazuh_thread.get_status() if hasattr(wazuh_thread, "get_status") else {}
        return {"status": "already running", "mode": "behavior", "runtime": runtime}

    started = start_wazuh_monitor_from_runtime(current_user["username"])
    if not started:
        raise HTTPException(status_code=500, detail="Behavior detection could not start.")
    runtime = wazuh_thread.get_status() if hasattr(wazuh_thread, "get_status") else {}
    return {"status": "started", "mode": "behavior", "runtime": runtime}


@app.post("/api/wazuh/select-alert-log")
def select_wazuh_alert_log(payload: dict | None = None, current_user: dict = Depends(require_auth)):
    global selected_wazuh_alert_log
    requested_path = (payload or {}).get("path")
    selected_path = validate_wazuh_alert_log(requested_path) if requested_path else choose_wazuh_alert_log_dialog()
    if not selected_path:
        return {"status": "cancelled"}
    selected_wazuh_alert_log = selected_path
    os.environ["WAZUH_ALERT_LOG_PATH"] = selected_path
    broadcast_log("wazuh", f"Selected Wazuh alerts log: {selected_path}", current_user["username"])
    return {
        "status": "selected",
        "log_path": selected_path,
        "runtime": get_wazuh_runtime_state(),
    }


@app.get("/api/wazuh/setup-status")
def get_wazuh_setup_status(current_user: dict = Depends(require_auth)):
    return get_wazuh_setup_job_snapshot()


@app.post("/api/wazuh/setup-manager")
def setup_wazuh_manager(payload: dict | None = None, current_user: dict = Depends(require_auth)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    if os.name != "nt":
        raise HTTPException(status_code=400, detail="This setup helper is written for the Windows project host.")
    if not WAZUH_MANAGER_INSTALL_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Missing setup script: {WAZUH_MANAGER_INSTALL_SCRIPT}")
    if not WAZUH_ALERTS_BRIDGE_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Missing bridge script: {WAZUH_ALERTS_BRIDGE_SCRIPT}")

    payload = payload or {}
    host = validate_setup_host(payload.get("host"))
    user = validate_setup_user(payload.get("user", ""))
    port = validate_setup_port(payload.get("port", 22))
    agent_manager_address = sanitize_setup_text(payload.get("agent_manager_address"), default=host)
    if agent_manager_address:
        validate_setup_host(agent_manager_address)

    with WAZUH_SETUP_LOCK:
        if WAZUH_SETUP_JOB["running"]:
            return dict(WAZUH_SETUP_JOB)
        WAZUH_SETUP_JOB.update({
            "running": True,
            "status": "queued",
            "message": "Wazuh Manager setup queued.",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "finished_at": None,
            "host": host,
            "log": [],
            "returncode": None,
        })

    setup_payload = {
        "host": host,
        "user": user,
        "port": port,
        "agent_manager_address": agent_manager_address,
    }
    Thread(
        target=wazuh_manager_setup_worker,
        args=(setup_payload, current_user["username"]),
        daemon=True,
    ).start()
    broadcast_log("wazuh", f"Wazuh Manager CLI setup started for {host}.", current_user["username"])
    return get_wazuh_setup_job_snapshot()


@app.post("/api/wazuh/setup-wsl-manager")
def setup_wazuh_wsl_manager(payload: dict | None = None, current_user: dict = Depends(require_auth)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    if os.name != "nt":
        raise HTTPException(status_code=400, detail="This setup helper is written for the Windows project host.")
    if not WAZUH_WSL_SETUP_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Missing WSL setup script: {WAZUH_WSL_SETUP_SCRIPT}")
    if not WAZUH_WSL_ALERTS_BRIDGE_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"Missing WSL bridge script: {WAZUH_WSL_ALERTS_BRIDGE_SCRIPT}")

    payload = payload or {}
    distro = validate_wsl_distro(payload.get("distro", "Ubuntu"))

    with WAZUH_SETUP_LOCK:
        if WAZUH_SETUP_JOB["running"]:
            return dict(WAZUH_SETUP_JOB)
        WAZUH_SETUP_JOB.update({
            "running": True,
            "status": "wsl_setup_window_launched",
            "message": "WSL Wazuh Manager setup window was launched. Approve UAC and follow the PowerShell/Ubuntu prompts.",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "finished_at": None,
            "host": f"wsl:{distro}",
            "log": [],
            "returncode": None,
        })

    command = [
        "powershell.exe",
        "-NoExit",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(WAZUH_WSL_SETUP_SCRIPT),
        "-Distro",
        distro,
        "-InstallDistro",
        "-InstallCapstoneRules",
        "-StartBridge",
    ]
    process = launch_visible_setup_window(command)
    append_wazuh_setup_log(f"Visible WSL setup window started with pid={process.pid}.")
    update_wazuh_setup_job(
        running=False,
        status="wsl_setup_window_launched",
        message="WSL setup is running in a visible PowerShell window. After it finishes, press Wazuh start again if monitoring is not already running.",
        returncode=None,
    )
    broadcast_log("wazuh", f"WSL Wazuh Manager setup window launched for {distro}.", current_user["username"])
    return get_wazuh_setup_job_snapshot()


@app.post("/api/wazuh/stop")
def stop_wazuh(current_user: dict = Depends(require_auth)):
    global wazuh_thread
    stopped = False
    if wazuh_thread and wazuh_thread.is_alive():
        broadcast_log("wazuh", "Stopping behavior detection...", current_user["username"])
        wazuh_thread.stop()
        wazuh_thread = None
        stopped = True
    return {"status": "stopped" if stopped else "not running"}


def on_yara_finished():
    global yara_thread
    yara_thread = None


def on_yara_scan_finished():
    global yara_scan_thread
    yara_scan_thread = None


@app.post("/api/yara/start")
def start_yara(payload: dict | None = None, current_user: dict = Depends(require_auth)):
    global yara_thread, yara_scan_thread
    mode = (payload or {}).get("mode", "").strip().lower()
    is_deep_scan = mode == "deep" or (
        payload
        and isinstance(payload.get("target_paths"), list)
        and payload.get("rule_source") == "external"
    )

    active_thread = yara_scan_thread if is_deep_scan else yara_thread
    if active_thread and active_thread.is_alive():
        raise HTTPException(
            status_code=409,
            detail="YARA deep scan is already running." if is_deep_scan else "YARA realtime monitor is already running.",
        )

    selected_paths = []
    has_explicit_target_paths = False
    invalid_selected_paths = []
    if payload and isinstance(payload.get("target_paths"), list):
        has_explicit_target_paths = True
        seen_paths = set()
        for path in payload["target_paths"]:
            if not isinstance(path, str) or not path.strip():
                continue
            normalized_path = os.path.normpath(os.path.expanduser(path.strip()))
            if os.path.isdir(normalized_path):
                if normalized_path not in seen_paths:
                    selected_paths.append(normalized_path)
                    seen_paths.add(normalized_path)
            else:
                invalid_selected_paths.append(normalized_path)

    if has_explicit_target_paths and invalid_selected_paths and not selected_paths:
        message = "Selected scan folders are unavailable. Choose an existing folder."
        broadcast_log("yara", f"[Yara VERIFY] {message}", current_user["username"])
        raise HTTPException(status_code=400, detail=message)

    if not selected_paths and not is_deep_scan:
        selected_paths = get_default_yara_monitor_paths()

    if selected_paths:
        prefer_external = is_deep_scan or (has_explicit_target_paths and payload and payload.get("rule_source") == "external")
        rules_path, rule_source = select_yara_rules_path(prefer_external=prefer_external)
        if prefer_external and rule_source != "external":
            message = "External Yara rules are not installed. Run backend/rules/update_external_rules.ps1 first."
            broadcast_log("yara", f"[Yara VERIFY] {message}", current_user["username"])
            raise HTTPException(status_code=400, detail=message)
    else:
        if payload and payload.get("rule_source") == "external":
            message = "External Yara rules cannot be used for an all-drive scan. Select one or more folders."
            broadcast_log("yara", f"[Yara VERIFY] {message}", current_user["username"])
            raise HTTPException(status_code=400, detail=message)
        rules_path, rule_source = select_yara_rules_path(prefer_external=False)

    scan_scope = ", ".join(selected_paths) if selected_paths else "all detected drives"
    rule_label = YARA_RULE_SOURCE_LABELS[rule_source]
    scan_type = "deep scan" if is_deep_scan else "realtime monitor"
    broadcast_log("yara", f"[Yara VERIFY] Preparing {rule_label} Yara {scan_type} for: {scan_scope}", current_user["username"])
    scanner = YaraScanner(
        rules_path=rules_path,
        target_path=None,
        target_paths=selected_paths,
        callback=lambda msg, details=None: handle_yara_monitor_message(msg, current_user["username"], details),
        on_finished=on_yara_scan_finished if is_deep_scan else on_yara_finished,
        monitor_after_initial=not is_deep_scan,
    )
    if is_deep_scan:
        yara_scan_thread = scanner
    else:
        yara_thread = scanner
    scanner.start()
    return {
        "status": "started",
        "mode": "deep" if is_deep_scan else "realtime",
        "rule_source": rule_label,
        "rules_path": rules_path,
        "target_paths": selected_paths,
    }


@app.post("/api/yara/stop")
def stop_yara(current_user: dict = Depends(require_auth)):
    global yara_thread, yara_scan_thread
    stopped = False
    if yara_thread and yara_thread.is_alive():
        broadcast_log("yara", "[Yara VERIFY] Stopping Yara host scan...", current_user["username"])
        yara_thread.stop()
        yara_thread = None
        stopped = True
    if yara_scan_thread and yara_scan_thread.is_alive():
        broadcast_log("yara", "[Yara VERIFY] Stopping Yara deep scan...", current_user["username"])
        yara_scan_thread.stop()
        yara_scan_thread = None
        stopped = True
    if stopped:
        return {"status": "stopped"}
    return {"status": "not running"}


@app.post("/api/yara/scan/stop")
def stop_yara_scan(current_user: dict = Depends(require_auth)):
    global yara_scan_thread
    if yara_scan_thread and yara_scan_thread.is_alive():
        broadcast_log("yara", "[Yara VERIFY] Stopping Yara deep scan...", current_user["username"])
        yara_scan_thread.stop()
        yara_scan_thread = None
        return {"status": "stopped"}
    return {"status": "not running"}


@app.get("/api/yara/directories")
def list_yara_directories(current_user: dict = Depends(require_auth)):
    return {"directories": get_root_scan_directories()}


@app.post("/api/yara/directories/pick")
def pick_yara_directory(current_user: dict = Depends(require_auth)):
    selected_path = choose_scan_directory_dialog()
    if not selected_path:
        return {"status": "cancelled", "path": None, "directory": None}
    if not os.path.isdir(selected_path):
        raise HTTPException(status_code=400, detail="Selected path is not a folder.")
    return {
        "status": "selected",
        "path": selected_path,
        "directory": build_directory_entry(selected_path),
    }


@app.get("/api/yara/directories/children")
def list_yara_directory_children(path: str, current_user: dict = Depends(require_auth)):
    return {"directories": get_child_scan_directories(path)}


@app.get("/api/logs")
def get_logs_list(username: str | None = None, current_user: dict = Depends(require_auth)):
    target_username = resolve_log_username(current_user, username)
    return {
        "logs": build_log_entries(target_username),
        "logs_by_source": merge_log_dates(target_username),
        "username": target_username,
    }


@app.post("/api/logs/clear")
def clear_logs(current_user: dict = Depends(require_auth)):
    username = current_user["username"]
    deleted_db_rows = delete_logs_for_user(username)
    log_dir = build_user_log_dir(username)
    deleted_files = 0

    if os.path.isdir(log_dir):
        for root, _, files in os.walk(log_dir):
            deleted_files += len(files)
        shutil.rmtree(log_dir, ignore_errors=True)

    broadcast_log("response", f"[Response] Cleared stored logs for {username}.", username, persist=False)
    return {
        "status": "cleared",
        "deleted_db_rows": deleted_db_rows,
        "deleted_files": deleted_files,
    }


@app.post("/api/logs/{source}/{date}/clear")
def clear_logs_for_day(source: str, date: str, current_user: dict = Depends(require_auth)):
    normalized_source = sanitize_log_source(source)
    if not normalized_source:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown log source.")
    if not is_valid_log_date(date):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid log date.")

    username = current_user["username"]
    deleted_db_rows = delete_logs_for_user_on_date(username, normalized_source, date)

    file_path = build_log_file_path(normalized_source, date, username)
    deleted_files = 0
    if os.path.isfile(file_path):
        try:
            os.remove(file_path)
            deleted_files = 1
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete log file: {exc}",
            ) from exc

    broadcast_log(
        "response",
        f"[Response] Cleared {normalized_source} logs for {username} on {date}.",
        username,
        persist=False,
    )
    return {
        "status": "cleared",
        "source": normalized_source,
        "date": date,
        "deleted_db_rows": deleted_db_rows,
        "deleted_files": deleted_files,
    }


@app.get("/api/logs/{source}/{date}")
def get_log_content(source: str, date: str, username: str | None = None, current_user: dict = Depends(require_auth)):
    normalized_source = sanitize_log_source(source)
    if not normalized_source:
        return {"content": "Unknown log source."}

    target_username = resolve_log_username(current_user, username)
    file_path = build_log_file_path(normalized_source, date, target_username)
    parts = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file_handle:
            parts.append(file_handle.read().strip())

    db_content = get_db_log_content(normalized_source, date, target_username)
    if db_content:
        parts.append(db_content.strip())

    merged_lines = []
    seen_lines = set()
    for part in parts:
        for line in part.splitlines():
            normalized_line = line.strip()
            if not normalized_line or normalized_line in seen_lines:
                continue
            seen_lines.add(normalized_line)
            merged_lines.append(normalized_line)

    return {"content": "\n".join(merged_lines) if merged_lines else "Log file not found.", "username": target_username}


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    print("Startup complete. Running Web API on http://127.0.0.1:8000")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
