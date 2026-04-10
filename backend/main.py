import asyncio
import base64
import json
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
PROJECT_PACKAGE_ROOT = BASE_DIR.parent
if str(PROJECT_PACKAGE_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_PACKAGE_ROOT))

try:
    from backend.runtime_paths import app_root, bundle_root
    from backend.src.database import SessionLocal, SiemLog, init_db, save_log
    from backend.src.wazuh_monitor import WazuhMonitor
    from backend.src.yara_scanner import YaraScanner, scan_file_with_rules
except ModuleNotFoundError:
    from runtime_paths import app_root, bundle_root
    from src.database import SessionLocal, SiemLog, init_db, save_log
    from src.wazuh_monitor import WazuhMonitor
    from src.yara_scanner import YaraScanner, scan_file_with_rules

PROJECT_ROOT = app_root()
BUNDLE_ROOT = bundle_root()
RULES_PATH = str(BUNDLE_ROOT / "backend" / "rules" / "enhanced_rules.yar")
DEFAULT_WAZUH_ALERT_LOG = str(PROJECT_ROOT / "logs" / "wazuh_alerts.jsonl")
DEFAULT_TEST_ARTIFACT_DIR = str(PROJECT_ROOT / "logs" / "test_artifacts")
FRONTEND_DIR = BUNDLE_ROOT / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    init_db()
    yield


app = FastAPI(title="SIEM API", lifespan=lifespan)

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


def build_log_file_path(source: str, date_str: str):
    return os.path.join(PROJECT_ROOT, "logs", f"{source}_alerts_{date_str}.log")


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


def list_log_dates_by_source():
    log_dir = os.path.join(PROJECT_ROOT, "logs")
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


def merge_log_dates():
    combined = list_log_dates_by_source()
    db = SessionLocal()
    try:
        rows = db.query(SiemLog.source, SiemLog.message, SiemLog.timestamp).all()
        for source, message, timestamp in rows:
            normalized_source = sanitize_log_source(source)
            if not normalized_source or not timestamp:
                continue
            if not should_persist_log(normalized_source, message):
                continue

            date_str = timestamp.strftime("%Y-%m-%d")
            if date_str not in combined[normalized_source]:
                combined[normalized_source].append(date_str)
    finally:
        db.close()

    for source in combined:
        combined[source].sort(reverse=True)

    return combined


def get_db_log_content(source: str, date: str):
    db = SessionLocal()
    try:
        rows = (
            db.query(SiemLog)
            .filter(SiemLog.source == source)
            .order_by(SiemLog.timestamp.asc())
            .all()
        )
    finally:
        db.close()

    matching_lines = []
    for row in rows:
        if not row.timestamp or row.timestamp.strftime("%Y-%m-%d") != date:
            continue
        if not should_persist_log(source, row.message):
            continue
        matching_lines.append(f"[{row.timestamp.strftime('%H:%M:%S')}] {row.message}")

    return "\n".join(matching_lines)


def write_to_file_log(source: str, message: str):
    normalized_source = sanitize_log_source(source)
    if not normalized_source or not should_persist_log(normalized_source, message):
        return

    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")

    log_dir = os.path.join(PROJECT_ROOT, "logs")
    os.makedirs(log_dir, exist_ok=True)
    with open(build_log_file_path(normalized_source, date_str), "a", encoding="utf-8") as file_handle:
        file_handle.write(f"[{time_str}] {message}\n")


def broadcast_log(source: str, message: str):
    if should_persist_log(source, message):
        write_to_file_log(source, message)
        save_log(source, message)

    payload = {
        "source": source,
        "message": message,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }

    if loop and loop.is_running():
        for websocket in connected_websockets.copy():
            try:
                asyncio.run_coroutine_threadsafe(websocket.send_json(payload), loop)
            except Exception:
                pass


def recommend_response(level: int, file_path: str | None, yara_result: dict | None = None):
    actions = []

    if yara_result and yara_result.get("status") == "matched":
        actions.append("Isolate the affected endpoint from the network")
        actions.append("Quarantine or remove the matched file")
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


def list_incidents():
    with INCIDENTS_LOCK:
        return [incident.copy() for incident in INCIDENTS]


def get_incident(incident_id: str):
    with INCIDENTS_LOCK:
        for incident in INCIDENTS:
            if incident["id"] == incident_id:
                return incident
    return None


def append_wazuh_alert(alert: dict):
    os.makedirs(os.path.dirname(DEFAULT_WAZUH_ALERT_LOG), exist_ok=True)
    with open(DEFAULT_WAZUH_ALERT_LOG, "a", encoding="utf-8") as file_handle:
        file_handle.write(f"{json.dumps(alert, ensure_ascii=False)}\n")


def ensure_default_test_artifact():
    os.makedirs(DEFAULT_TEST_ARTIFACT_DIR, exist_ok=True)
    artifact_path = os.path.join(DEFAULT_TEST_ARTIFACT_DIR, "update.ps1")
    if not os.path.exists(artifact_path):
        with open(artifact_path, "w", encoding="utf-8") as file_handle:
            file_handle.write("Write-Output 'Mock suspicious PowerShell persistence script'\n")
    return artifact_path


def get_desktop_directory() -> Path:
    one_drive = os.environ.get("OneDrive")
    if one_drive:
        desktop = Path(one_drive) / "Desktop"
        if desktop.exists():
            return desktop
    return Path.home() / "Desktop"


def create_wazuh_runtime_test_script() -> str:
    desktop_dir = get_desktop_directory()
    desktop_dir.mkdir(parents=True, exist_ok=True)
    script_path = desktop_dir / "wazuh_runtime_test.ps1"
    marker_path = desktop_dir / "wazuh_runtime_marker.txt"
    script_body = (
        "# Harmless Wazuh runtime test artifact\n"
        "$banner = 'powershell -enc VEVTVA=='\n"
        "$decoded = [System.Convert]::FromBase64String('VEVTVA==')\n"
        "$webClient = 'Net.WebClient'\n"
        "$downloadString = 'DownloadString'\n"
        f"Set-Content -Path '{marker_path}' -Value 'Wazuh runtime test completed.'\n"
        "Write-Output 'Wazuh runtime test script executed.'\n"
    )
    script_path.write_text(script_body, encoding="utf-8")
    return str(script_path)


def trigger_wazuh_runtime_test(script_path: str) -> dict:
    invocation = f"& '{script_path}'"
    encoded_command = base64.b64encode(invocation.encode("utf-16le")).decode("ascii")
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", encoded_command,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except OSError as exc:
        return {
            "status": "error",
            "message": f"Failed to start the PowerShell runtime test: {exc}",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "The PowerShell runtime test timed out before finishing.",
        }

    if completed.returncode != 0:
        stderr = (completed.stderr or completed.stdout or "").strip()
        return {
            "status": "error",
            "message": f"PowerShell runtime test failed: {stderr or f'exit code {completed.returncode}'}",
        }

    return {
        "status": "executed",
        "message": "PowerShell runtime test executed successfully.",
    }


def run_yara_verification(file_path: str):
    broadcast_log("yara", f"[Yara VERIFY] Starting verification for: {file_path}")
    result = scan_file_with_rules(RULES_PATH, file_path)

    if result["status"] == "matched":
        match_names = ", ".join(result["matches"])
        broadcast_log("yara", f"[Yara DETECT] Verification hit for {file_path} | Rules Matched: {match_names}")
    elif result["status"] == "clean":
        broadcast_log("yara", f"[Yara VERIFY] No Yara rules matched for: {file_path}")
    else:
        broadcast_log("yara", f"[Yara VERIFY] {result['message']}")

    return result


def process_wazuh_alert(event: dict):
    message = event.get("message", "Received Wazuh event.")
    level = event.get("level", 0)
    file_path = event.get("file_path")
    groups = event.get("groups", [])

    broadcast_log("wazuh", message)

    yara_result = None
    if file_path:
        yara_result = run_yara_verification(file_path)
    else:
        broadcast_log("yara", "[Yara VERIFY] Skipped file verification because the Wazuh event did not include a file path.")

    risk_score, risk_label = calculate_risk(level, file_path, groups, yara_result)
    response_actions = recommend_response(level, file_path, yara_result)
    decision_hint = "delete" if risk_score >= 70 or (yara_result and yara_result.get("status") == "matched") else "keep"
    response_message = (
        f"Risk {risk_label.upper()} ({risk_score}) | Suggested decision: {decision_hint.upper()} | "
        + " ; ".join(response_actions)
    )
    broadcast_log("response", f"[Response] {response_message}")

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
        "yara_status": yara_result.get("status") if yara_result else "skipped",
        "yara_matches": yara_result.get("matches", []) if yara_result else [],
        "risk_score": risk_score,
        "risk_label": risk_label,
        "recommended_actions": response_actions,
        "suggested_decision": decision_hint,
    }
    store_incident(incident)


def handle_wazuh_event(event: dict):
    if event.get("kind") == "alert":
        Thread(target=process_wazuh_alert, args=(event,), daemon=True).start()
        return

    broadcast_log("wazuh", event.get("message", "Received Wazuh monitor status update."))


@app.get("/api/incidents")
def get_incidents():
    return {"incidents": list_incidents()}


@app.post("/api/incidents/{incident_id}/decision")
def decide_incident(incident_id: str, payload: dict):
    incident = get_incident(incident_id)
    if not incident:
        return {
            "status": "not found",
            "result_message": "Incident not found.",
            "result_type": "error",
        }

    action = (payload or {}).get("action", "").strip().lower()
    if action not in {"delete", "keep"}:
        return {
            "status": "invalid action",
            "result_message": "Invalid incident action.",
            "result_type": "error",
        }

    if action == "delete":
        file_path = incident.get("file_path")
        if not file_path:
            incident["status"] = "error"
            incident["decision"] = "delete"
            incident["decision_note"] = "No file path was available for deletion."
            broadcast_log("response", f"[Response] Delete failed for incident {incident_id}: no file path available.")
            return {
                "status": "error",
                "incident": incident.copy(),
                "result_message": "Delete failed: no file path was available.",
                "result_type": "error",
            }

        if not os.path.exists(file_path):
            incident["status"] = "deleted"
            incident["decision"] = "delete"
            incident["decision_note"] = "File was already missing when delete was requested."
            broadcast_log("response", f"[Response] File already absent for incident {incident_id}: {file_path}")
            return {
                "status": "deleted",
                "incident": incident.copy(),
                "result_message": f"Delete success: file was already absent. {file_path}",
                "result_type": "success",
            }

        if not os.path.isfile(file_path):
            incident["status"] = "error"
            incident["decision"] = "delete"
            incident["decision_note"] = "Target path is not a file."
            broadcast_log("response", f"[Response] Delete failed for incident {incident_id}: target is not a file.")
            return {
                "status": "error",
                "incident": incident.copy(),
                "result_message": f"Delete failed: target path is not a file. {file_path}",
                "result_type": "error",
            }

        try:
            os.remove(file_path)
            deleted = not os.path.exists(file_path)
            incident["status"] = "deleted"
            incident["decision"] = "delete"
            incident["decision_note"] = f"File deleted: {file_path}" if deleted else f"Delete was attempted, but the file still exists: {file_path}"
            if deleted:
                broadcast_log("response", f"[Response] File deleted for incident {incident_id}: {file_path}")
                return {
                    "status": "deleted",
                    "incident": incident.copy(),
                    "result_message": f"Delete success: file removed. {file_path}",
                    "result_type": "success",
                }

            incident["status"] = "error"
            incident["decision_note"] = f"Delete failed: file still exists after os.remove. {file_path}"
            broadcast_log("response", f"[Response] Delete failed for incident {incident_id}: file still exists after removal attempt.")
            return {
                "status": "error",
                "incident": incident.copy(),
                "result_message": f"Delete failed: file still exists after removal attempt. {file_path}",
                "result_type": "error",
            }
        except OSError as exc:
            incident["status"] = "error"
            incident["decision"] = "delete"
            incident["decision_note"] = f"Delete failed: {exc}"
            broadcast_log("response", f"[Response] Delete failed for incident {incident_id}: {exc}")
            return {
                "status": "error",
                "incident": incident.copy(),
                "result_message": f"Delete failed: {exc}",
                "result_type": "error",
            }

    incident["status"] = "kept"
    incident["decision"] = "keep"
    incident["decision_note"] = "Analyst chose to keep the file and continue monitoring."
    broadcast_log("response", f"[Response] Incident {incident_id} marked as kept for monitoring.")
    return {
        "status": "kept",
        "incident": incident.copy(),
        "result_message": "Incident marked as kept for monitoring.",
        "result_type": "info",
    }


@app.post("/api/incidents/{incident_id}/open-folder")
def open_incident_folder(incident_id: str):
    incident = get_incident(incident_id)
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
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)
    except Exception:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)


@app.get("/api/status")
def get_status():
    return {
        "wazuh_running": wazuh_thread.is_alive() if wazuh_thread else False,
        "yara_running": yara_thread.is_alive() if yara_thread else False,
    }


@app.post("/api/wazuh/start")
def start_wazuh():
    global wazuh_thread
    if wazuh_thread and wazuh_thread.is_alive():
        return {"status": "already running"}

    os.makedirs(os.path.dirname(DEFAULT_WAZUH_ALERT_LOG), exist_ok=True)
    if not os.path.exists(DEFAULT_WAZUH_ALERT_LOG):
        Path(DEFAULT_WAZUH_ALERT_LOG).touch()

    broadcast_log("wazuh", "Starting Wazuh event monitoring...")
    wazuh_thread = WazuhMonitor(
        log_path=DEFAULT_WAZUH_ALERT_LOG,
        callback=handle_wazuh_event,
        replay_existing=False,
    )
    wazuh_thread.start()
    return {"status": "started"}


@app.post("/api/wazuh/stop")
def stop_wazuh():
    global wazuh_thread
    if wazuh_thread and wazuh_thread.is_alive():
        broadcast_log("wazuh", "Stopping Wazuh event monitoring...")
        wazuh_thread.stop()
        wazuh_thread = None
        return {"status": "stopped"}
    return {"status": "not running"}


@app.post("/api/wazuh/test-alert")
def create_test_wazuh_alert(payload: dict | None = None):
    requested_path = None
    if payload and isinstance(payload.get("file_path"), str):
        requested_path = payload["file_path"].strip()

    if requested_path and not os.path.isfile(requested_path):
        return {
            "status": "error",
            "message": f"Requested test file does not exist: {requested_path}",
        }

    test_file_path = requested_path or create_wazuh_runtime_test_script()
    runtime_result = trigger_wazuh_runtime_test(test_file_path)

    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "agent": {
            "name": "win-lab-endpoint",
        },
        "rule": {
            "level": 10,
            "description": "Suspicious PowerShell persistence behavior",
            "groups": ["sysmon", "malware", "persistence"],
        },
        "syscheck": {
            "path": test_file_path,
        },
    }
    append_wazuh_alert(alert)
    return {
        "status": "queued",
        "alert": alert,
        "runtime_test": runtime_result,
    }


def on_yara_finished():
    global yara_thread
    yara_thread = None


@app.post("/api/yara/start")
def start_yara(payload: dict | None = None):
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

    scan_scope = ", ".join(selected_paths) if selected_paths else "all detected drives"
    broadcast_log("yara", f"[Yara VERIFY] Preparing Yara scan for: {scan_scope}")
    yara_thread = YaraScanner(
        rules_path=RULES_PATH,
        target_path=None,
        target_paths=selected_paths,
        callback=lambda msg: broadcast_log("yara", msg),
        on_finished=on_yara_finished,
    )
    yara_thread.start()
    return {"status": "started"}


@app.post("/api/yara/stop")
def stop_yara():
    global yara_thread
    if yara_thread and yara_thread.is_alive():
        broadcast_log("yara", "[Yara VERIFY] Stopping Yara host scan...")
        yara_thread.stop()
        yara_thread = None
        return {"status": "stopped"}
    return {"status": "not running"}


@app.get("/api/yara/directories")
def list_yara_directories():
    return {"directories": get_root_scan_directories()}


@app.get("/api/yara/directories/children")
def list_yara_directory_children(path: str):
    return {"directories": get_child_scan_directories(path)}


@app.get("/api/logs")
def get_logs_list():
    return {"logs": merge_log_dates()}


@app.get("/api/logs/{source}/{date}")
def get_log_content(source: str, date: str):
    normalized_source = sanitize_log_source(source)
    if not normalized_source:
        return {"content": "Unknown log source."}

    file_path = build_log_file_path(normalized_source, date)
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file_handle:
            return {"content": file_handle.read()}

    db_content = get_db_log_content(normalized_source, date)
    if db_content:
        return {"content": db_content}

    return {"content": "Log file not found."}


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    print("Startup complete. Running Web API on http://127.0.0.1:8000")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
