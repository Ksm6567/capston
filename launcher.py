import socket
import threading
import time

import uvicorn
import webview

from backend.main import app


HOST = "127.0.0.1"
PORT = 8000
APP_URL = f"http://{HOST}:{PORT}/"


def wait_for_server(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.25)
    return False


def run_server() -> None:
    uvicorn.run(app, host=HOST, port=PORT, reload=False, log_level="info")


if __name__ == "__main__":
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    if wait_for_server(HOST, PORT):
        window = webview.create_window(
            "Capstone SIEM",
            APP_URL,
            width=1440,
            height=920,
            min_size=(1100, 720),
        )
        webview.start()
