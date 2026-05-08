import asyncio
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
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
DEFAULT_WAZUH_ALERT_LOG = os.getenv(
    "WAZUH_ALERT_LOG_PATH",
    str(PROJECT_ROOT / "logs" / "wazuh_alerts.jsonl"),
)
FRONTEND_DIR = BUNDLE_ROOT / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    init_db()
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
yara_thread = None
connected_websockets = []
loop = None
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
    "sysmon", "defender", "evasion",
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
        return "[wazuh alert]" in normalized_message
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


def broadcast_log(source: str, message: str, username: str | None = None, persist: bool = True):
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
        actions.append("Preserve the host and Wazuh logs for triage")
    elif level >= 10:
        actions.append("Prioritize analyst triage and isolate the host if behavior persists")
        actions.append("Inspect the originating process tree and scheduled tasks")
    elif level >= 6:
        actions.append("Review the alert in the Wazuh dashboard and validate the endpoint context")
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


def store_incident(incident: dict):
    with INCIDENTS_LOCK:
        INCIDENTS.insert(0, incident)
        del INCIDENTS[MAX_INCIDENTS:]


def list_incidents(username: str):
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


def quarantine_incident_file(incident: dict, username: str):
    file_path = incident.get("file_path")
    if not file_path:
        return "error", "Quarantine failed: no file path was available.", "error"
    if not os.path.isfile(file_path):
        return "error", f"Quarantine failed: target file does not exist. {file_path}", "error"

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

    incident["file_path"] = str(target_path)
    incident["file_exists"] = True
    incident["quarantine_original_path"] = file_path
    incident["quarantine_path"] = str(target_path)
    incident["file_sha256"] = file_hash
    return "quarantined", f"Quarantine success: file moved to {target_path}", "success"


def terminate_incident_process(incident: dict):
    pid = parse_process_id(incident.get("process_id"))
    if not pid:
        return "error", "Terminate failed: no process ID was captured from the Wazuh alert.", "error"
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
        message = (completed.stderr or completed.stdout or "").strip()
        return "error", f"Terminate failed for PID {pid}: {message or completed.returncode}", "error"

    incident["process_terminated"] = True
    return "terminated", f"Terminate success: process tree for PID {pid} was stopped.", "success"


def block_incident_ip(incident: dict):
    destination_ip = (incident.get("destination_ip") or "").strip()
    if not destination_ip:
        return "error", "Block IP failed: no destination IP was captured from the Wazuh alert.", "error"

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
        message = (completed.stderr or completed.stdout or "").strip()
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
    message = event.get("message", "Received Wazuh event.")
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
        broadcast_log("yara", "[Yara VERIFY] Skipped file verification because the Wazuh event did not include a file path.", username)

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


def handle_wazuh_event(event: dict):
    if event.get("kind") == "alert":
        Thread(target=process_wazuh_alert, args=(event,), daemon=True).start()
        return

    broadcast_log("wazuh", event.get("message", "Received Wazuh monitor status update."), event.get("username"))


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

    if action == "quarantine":
        status_value, result_message, result_type = quarantine_incident_file(incident, current_user["username"])
    elif action == "terminate_process":
        status_value, result_message, result_type = terminate_incident_process(incident)
    elif action == "block_ip":
        status_value, result_message, result_type = block_incident_ip(incident)
    else:
        status_value, result_message, result_type = "kept", "Incident marked as kept for monitoring.", "info"

    if status_value != "error":
        incident["status"] = status_value
    incident["decision"] = action
    incident["decision_note"] = result_message
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
    return {
        "wazuh_running": wazuh_thread.is_alive() if wazuh_thread else False,
        "yara_running": yara_thread.is_alive() if yara_thread else False,
        "username": current_user["username"],
    }


@app.post("/api/wazuh/start")
def start_wazuh(current_user: dict = Depends(require_auth)):
    global wazuh_thread
    if wazuh_thread and wazuh_thread.is_alive():
        return {"status": "already running"}

    os.makedirs(os.path.dirname(DEFAULT_WAZUH_ALERT_LOG), exist_ok=True)
    if not os.path.exists(DEFAULT_WAZUH_ALERT_LOG):
        Path(DEFAULT_WAZUH_ALERT_LOG).touch()

    broadcast_log("wazuh", "Starting Wazuh event monitoring...", current_user["username"])
    wazuh_thread = WazuhMonitor(
        log_path=DEFAULT_WAZUH_ALERT_LOG,
        callback=lambda event: handle_wazuh_event({
            **event,
            "username": event.get("username") or current_user["username"],
        }),
        replay_existing=False,
    )
    wazuh_thread.start()
    return {"status": "started"}


@app.post("/api/wazuh/stop")
def stop_wazuh(current_user: dict = Depends(require_auth)):
    global wazuh_thread
    if wazuh_thread and wazuh_thread.is_alive():
        broadcast_log("wazuh", "Stopping Wazuh event monitoring...", current_user["username"])
        wazuh_thread.stop()
        wazuh_thread = None
        return {"status": "stopped"}
    return {"status": "not running"}


def on_yara_finished():
    global yara_thread
    yara_thread = None


@app.post("/api/yara/start")
def start_yara(payload: dict | None = None, current_user: dict = Depends(require_auth)):
    global yara_thread
    if yara_thread and yara_thread.is_alive():
        return {"status": "already running"}

    selected_paths = []
    if payload and isinstance(payload.get("target_paths"), list):
        selected_paths = [
            os.path.normpath(path)
            for path in payload["target_paths"]
            if isinstance(path, str) and path.strip()
        ]

    if selected_paths:
        rules_path, rule_source = select_yara_rules_path(prefer_external=True)
        if rule_source != "external":
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
    broadcast_log("yara", f"[Yara VERIFY] Preparing {rule_label} Yara scan for: {scan_scope}", current_user["username"])
    yara_thread = YaraScanner(
        rules_path=rules_path,
        target_path=None,
        target_paths=selected_paths,
        callback=lambda msg: broadcast_log("yara", msg, current_user["username"]),
        on_finished=on_yara_finished,
    )
    yara_thread.start()
    return {"status": "started", "rule_source": rule_label, "rules_path": rules_path}


@app.post("/api/yara/stop")
def stop_yara(current_user: dict = Depends(require_auth)):
    global yara_thread
    if yara_thread and yara_thread.is_alive():
        broadcast_log("yara", "[Yara VERIFY] Stopping Yara host scan...", current_user["username"])
        yara_thread.stop()
        yara_thread = None
        return {"status": "stopped"}
    return {"status": "not running"}


@app.get("/api/yara/directories")
def list_yara_directories(current_user: dict = Depends(require_auth)):
    return {"directories": get_root_scan_directories()}


@app.get("/api/yara/directories/children")
def list_yara_directory_children(path: str, current_user: dict = Depends(require_auth)):
    return {"directories": get_child_scan_directories(path)}


@app.get("/api/logs")
def get_logs_list(username: str | None = None, current_user: dict = Depends(require_auth)):
    target_username = resolve_log_username(current_user, username)
    return {"logs": merge_log_dates(target_username), "username": target_username}


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
