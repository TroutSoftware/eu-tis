#!/usr/bin/env python3

import argparse
import json
import os
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PLC_HOST = os.environ.get("PLC_HOST", "198.18.40.10")
PLC_PORT = int(os.environ.get("PLC_PORT", "502"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "2"))
MQTT_HOST = os.environ.get("MQTT_HOST", "")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))

TAG_DEFINITIONS = {
    "tank_level_pct": 0.1,
    "setpoint_pct": 0.1,
    "inlet_flow_lpm": 0.1,
    "outlet_flow_lpm": 0.1,
    "pump_running": 1.0,
    "alarm_high": 1.0,
    "alarm_low": 1.0,
    "plc_healthy": 1.0,
}

TAG_NAMES = list(TAG_DEFINITIONS.keys())
STATE = {
    "tags": {tag: 0 for tag in TAG_NAMES},
    "updated_at": 0,
    "mqtt_reachable": False,
    "status": "starting",
}
STATE_LOCK = threading.Lock()


def read_holding_registers(host: str, port: int, start: int, quantity: int) -> list[int]:
    transaction_id = int(time.time() * 1000) & 0xFFFF
    pdu = struct.pack(">BHH", 3, start, quantity)
    request = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, 1) + pdu

    with socket.create_connection((host, port), timeout=2) as sock:
        sock.sendall(request)
        response = sock.recv(512)

    if len(response) < 9:
        raise RuntimeError("Short Modbus response")

    function_code = response[7]
    if function_code & 0x80:
        raise RuntimeError("Modbus exception response")

    byte_count = response[8]
    registers = []
    for offset in range(0, byte_count, 2):
        registers.append(struct.unpack(">H", response[9 + offset : 11 + offset])[0])
    return registers


def mqtt_reachable() -> bool:
    if not MQTT_HOST:
        return False

    try:
        with socket.create_connection((MQTT_HOST, MQTT_PORT), timeout=2):
            return True
    except OSError:
        return False


def poll_loop() -> None:
    while True:
        try:
            registers = read_holding_registers(PLC_HOST, PLC_PORT, 0, len(TAG_NAMES))
            tags = {}
            for name, value in zip(TAG_NAMES, registers):
                scale = TAG_DEFINITIONS[name]
                if scale == 1.0:
                    tags[name] = int(value)
                else:
                    tags[name] = round(value * scale, 2)

            with STATE_LOCK:
                STATE["tags"] = tags
                STATE["updated_at"] = time.time()
                STATE["mqtt_reachable"] = mqtt_reachable()
                STATE["status"] = "ok"
        except Exception as exc:
            with STATE_LOCK:
                STATE["status"] = f"degraded: {exc}"
                STATE["updated_at"] = time.time()
                STATE["mqtt_reachable"] = mqtt_reachable()
        time.sleep(POLL_INTERVAL)


def make_handler():
    class Handler(BaseHTTPRequestHandler):
        def _write_json(self, status_code: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            with STATE_LOCK:
                state = dict(STATE)

            if self.path == "/health":
                self._write_json(200, {"status": state["status"]})
                return

            if self.path in {"/", "/api/tags"}:
                self._write_json(200, state)
                return

            self._write_json(404, {"error": "not_found"})

        def log_message(self, fmt: str, *args) -> None:
            return

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple SCADA API backed by PLC polling.")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()

    threading.Thread(target=poll_loop, daemon=True).start()
    server = ThreadingHTTPServer((args.listen, args.port), make_handler())
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
