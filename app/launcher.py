"""
Application launcher for Explainable Adaptive IDS.
Binds FastAPI backend to loopback 127.0.0.1 with ephemeral port,
generates a per-session authentication token, and opens pywebview desktop window.
"""
import sys
import os
import time
import socket
import logging
import threading
from typing import Tuple
import urllib.request
import urllib.error

# Ensure project root is in sys.path
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import uvicorn
import webview

from app.main import app
from backend.api.auth import generate_session_token, set_session_token
from app.lifecycle import on_shutdown

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [LAUNCHER] %(message)s")
logger = logging.getLogger("IDS.Launcher")


def find_free_port(host: str = "127.0.0.1") -> int:
    """Find an available ephemeral port on the loopback interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        s.listen(1)
        return s.getsockname()[1]


class BackendServerThread(threading.Thread):
    """Managed daemon thread hosting the Uvicorn server."""
    def __init__(self, host: str, port: int):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.server = None

    def run(self):
        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level="warning",
            access_log=False
        )
        self.server = uvicorn.Server(config)
        self.server.run()

    def stop(self):
        if self.server:
            self.server.should_exit = True


def wait_for_server(host: str, port: int, timeout_sec: float = 10.0) -> bool:
    """Poll the backend health endpoint until it responds successfully."""
    url = f"http://{host}:{port}/api/health"
    start_time = time.time()
    while time.time() - start_time < timeout_sec:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IDS-Launcher"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionRefusedError, socket.timeout):
            time.sleep(0.1)
    return False


def launch(headless: bool = False, open_browser: bool = False) -> None:
    """Launch backend server and open pywebview desktop window or browser."""
    host = "127.0.0.1"
    port = find_free_port(host)
    token = generate_session_token()
    set_session_token(token)

    logger.info(f"Starting local backend on http://{host}:{port} with session security...")
    server_thread = BackendServerThread(host, port)
    server_thread.start()

    if not wait_for_server(host, port, timeout_sec=12.0):
        logger.error("Failed to verify backend health within timeout window. Aborting.")
        server_thread.stop()
        sys.exit(1)

    logger.info("Backend is healthy and listening on loopback.")
    frontend_url = f"http://{host}:{port}/static/index.html?token={token}"

    if open_browser:
        import webbrowser
        logger.info(f"Opening default browser (Safari): {frontend_url}")
        webbrowser.open(frontend_url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Termination signal received.")
        finally:
            on_shutdown()
            server_thread.stop()
        return

    if headless:
        logger.info("Running in headless mode (--headless). Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Termination signal received.")
        finally:
            on_shutdown()
            server_thread.stop()
        return

    logger.info("Creating dedicated desktop application window via pywebview...")
    try:
        window = webview.create_window(
            title="Explainable Adaptive IDS",
            url=frontend_url,
            width=1240,
            height=820,
            min_size=(960, 640),
            confirm_close=False
        )

        def on_closed():
            logger.info("Desktop window closed by user. Cleaning up...")
            on_shutdown()
            server_thread.stop()

        window.events.closed += on_closed
        webview.start(debug=False)

    except Exception as exc:
        logger.error(f"Error launching pywebview window: {exc}")
        on_shutdown()
        server_thread.stop()
        raise exc


if __name__ == "__main__":
    is_headless = "--headless" in sys.argv or "--server-only" in sys.argv
    use_browser = "--browser" in sys.argv
    launch(headless=is_headless, open_browser=use_browser)
