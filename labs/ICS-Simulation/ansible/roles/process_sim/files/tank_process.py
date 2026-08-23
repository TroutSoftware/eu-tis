#!/usr/bin/env python3

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class ProcessState:
    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self.lock = threading.Lock()
        self.state = {
            "tank_level_pct": 52.0,
            "setpoint_pct": 55.0,
            "inlet_flow_lpm": 12.0,
            "outlet_flow_lpm": 9.0,
            "pump_running": 1,
            "alarm_high": 0,
            "alarm_low": 0,
            "updated_at": time.time(),
        }

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self.state)

    def apply_command(self, payload: dict) -> dict:
        with self.lock:
            if "setpoint_pct" in payload:
                self.state["setpoint_pct"] = max(5.0, min(95.0, float(payload["setpoint_pct"])))
            if "pump_running" in payload:
                self.state["pump_running"] = 1 if int(payload["pump_running"]) else 0
            self.state["updated_at"] = time.time()
            return dict(self.state)

    def tick(self) -> None:
        while True:
            with self.lock:
                level = self.state["tank_level_pct"]
                setpoint = self.state["setpoint_pct"]
                pump_running = self.state["pump_running"]

                if level < setpoint - 3:
                    pump_running = 1
                elif level > setpoint + 3:
                    pump_running = 0

                inlet_flow = 14.0 if pump_running else 2.0
                outlet_flow = 9.0 + (level / 100.0) * 4.0
                level += (inlet_flow - outlet_flow) / 30.0
                level = max(0.0, min(100.0, level))

                self.state.update(
                    {
                        "tank_level_pct": round(level, 2),
                        "inlet_flow_lpm": round(inlet_flow, 2),
                        "outlet_flow_lpm": round(outlet_flow, 2),
                        "pump_running": pump_running,
                        "alarm_high": 1 if level >= 85 else 0,
                        "alarm_low": 1 if level <= 15 else 0,
                        "updated_at": time.time(),
                    }
                )
                self.state_file.write_text(json.dumps(self.state, indent=2))

            time.sleep(1.0)


def make_handler(process_state: ProcessState):
    class Handler(BaseHTTPRequestHandler):
        def _write_json(self, status_code: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path in {"/", "/state"}:
                self._write_json(200, process_state.snapshot())
                return

            if self.path == "/health":
                self._write_json(200, {"status": "ok"})
                return

            self._write_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/command":
                self._write_json(404, {"error": "not_found"})
                return

            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode() if length else "{}"
            payload = json.loads(body or "{}")
            self._write_json(200, process_state.apply_command(payload))

        def log_message(self, fmt: str, *args) -> None:
            return

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple tank process simulator.")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--state-file", default="/var/lib/ics-process/state.json")
    args = parser.parse_args()

    state = ProcessState(Path(args.state_file))
    state.state_file.parent.mkdir(parents=True, exist_ok=True)
    state.state_file.write_text(json.dumps(state.snapshot(), indent=2))

    worker = threading.Thread(target=state.tick, daemon=True)
    worker.start()

    server = ThreadingHTTPServer((args.listen, args.port), make_handler(state))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
