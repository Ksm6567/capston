import os
import sys
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

sys.path.append(os.path.join(BASE_DIR, 'src'))
from suricata_monitor import SuricataMonitor
from yara_scanner import YaraScanner
from database import init_db, save_log, SessionLocal, SiemLog

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

suricata_thread = None
yara_thread = None
connected_websockets = []
loop = None


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


def write_to_file_log(message: str):
    exclude_keywords = ["Waiting for", "System Initialized", "Starting", "Stopping", "stopped", "Monitoring", "Compiling", "Engine Ready"]
    if any(kw in message for kw in exclude_keywords):
        return

    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")

    log_dir = os.path.join(PROJECT_ROOT, "logs")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, f"siem_alerts_{date_str}.log"), "a", encoding="utf-8") as f:
        f.write(f"[{time_str}] {message}\n")


def broadcast_log(source: str, message: str):
    write_to_file_log(message)
    save_log(source, message)
    payload = {
        "source": source,
        "message": message,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }

    if loop and loop.is_running():
        for ws in connected_websockets.copy():
            try:
                asyncio.run_coroutine_threadsafe(ws.send_json(payload), loop)
            except Exception:
                pass


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
        "suricata_running": suricata_thread.is_alive() if suricata_thread else False,
        "yara_running": yara_thread.is_alive() if yara_thread else False,
    }


@app.post("/api/suricata/start")
def start_suricata():
    global suricata_thread
    if suricata_thread and suricata_thread.is_alive():
        return {"status": "already running"}

    broadcast_log("suricata", "Starting Suricata Network Detection...")
    suricata_thread = SuricataMonitor(
        log_path=os.path.join(PROJECT_ROOT, "eve.json"),
        callback=lambda msg: broadcast_log("suricata", msg),
    )
    suricata_thread.start()
    return {"status": "started"}


@app.post("/api/suricata/stop")
def stop_suricata():
    global suricata_thread
    if suricata_thread and suricata_thread.is_alive():
        broadcast_log("suricata", "Stopping Suricata Network Detection...")
        suricata_thread.stop()
        suricata_thread = None
        return {"status": "stopped"}
    return {"status": "not running"}


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
    broadcast_log("yara", f"Preparing Yara scan for: {scan_scope}")
    yara_thread = YaraScanner(
        rules_path=os.path.join(BASE_DIR, "rules", "enhanced_rules.yar"),
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
        broadcast_log("yara", "Stopping Yara Host Scan...")
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
    log_dir = os.path.join(PROJECT_ROOT, "logs")
    if not os.path.exists(log_dir):
        return {"logs": []}
    files = [f for f in os.listdir(log_dir) if f.startswith("siem_alerts_") and f.endswith(".log")]
    dates = [f.replace("siem_alerts_", "").replace(".log", "") for f in files]
    dates.sort(reverse=True)
    return {"logs": dates}


@app.get("/api/logs/{date}")
def get_log_content(date: str):
    file_path = os.path.join(PROJECT_ROOT, "logs", f"siem_alerts_{date}.log")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return {"content": f.read()}
    return {"content": "Log file not found."}


if __name__ == "__main__":
    print("Startup complete. Running Web API on http://127.0.0.1:8000")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
