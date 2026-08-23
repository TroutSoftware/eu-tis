#!/usr/bin/env python3

import argparse
import json
import os
import socket
import struct
import threading
import time
import urllib.request
from pathlib import Path


PROCESS_STATE_URL = os.environ.get("PROCESS_STATE_URL", "http://198.18.40.20:8080/state")
PROCESS_COMMAND_URL = os.environ.get("PROCESS_COMMAND_URL", "http://198.18.40.20:8080/command")


class RegisterBank:
    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self.lock = threading.Lock()
        self.registers = [0] * 16

    def _write_state(self) -> None:
        payload = {
            "registers": self.registers,
            "updated_at": time.time(),
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(payload, indent=2))

    def update_from_process(self) -> None:
        while True:
            try:
                with urllib.request.urlopen(PROCESS_STATE_URL, timeout=2) as response:
                    payload = json.loads(response.read().decode())
                with self.lock:
                    self.registers[0] = int(round(float(payload["tank_level_pct"]) * 10))
                    self.registers[1] = int(round(float(payload["setpoint_pct"]) * 10))
                    self.registers[2] = int(round(float(payload["inlet_flow_lpm"]) * 10))
                    self.registers[3] = int(round(float(payload["outlet_flow_lpm"]) * 10))
                    self.registers[4] = int(payload["pump_running"])
                    self.registers[5] = int(payload["alarm_high"])
                    self.registers[6] = int(payload["alarm_low"])
                    self.registers[7] = 1
                    self._write_state()
            except Exception:
                with self.lock:
                    self.registers[7] = 0
                    self._write_state()
            time.sleep(2.0)

    def read(self, start: int, quantity: int) -> list[int]:
        with self.lock:
            return self.registers[start : start + quantity]

    def write_single(self, address: int, value: int) -> None:
        payload = {}
        if address == 1:
            payload["setpoint_pct"] = value / 10.0
        elif address == 4:
            payload["pump_running"] = 1 if value else 0
        else:
            return

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            PROCESS_COMMAND_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2):
            pass


def handle_client(connection: socket.socket, bank: RegisterBank) -> None:
    with connection:
        request = connection.recv(260)
        if len(request) < 12:
            return

        transaction_id, protocol_id, length = struct.unpack(">HHH", request[:6])
        unit_id = request[6]
        function_code = request[7]

        if protocol_id != 0:
            return

        if function_code == 3:
            start_address, quantity = struct.unpack(">HH", request[8:12])
            values = bank.read(start_address, quantity)
            data = b"".join(struct.pack(">H", value) for value in values)
            pdu = bytes([function_code, len(data)]) + data
        elif function_code == 6:
            address, value = struct.unpack(">HH", request[8:12])
            bank.write_single(address, value)
            pdu = bytes([function_code]) + struct.pack(">HH", address, value)
        else:
            pdu = bytes([function_code | 0x80, 0x01])

        response = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id) + pdu
        connection.sendall(response)


def serve(listen: str, port: int, bank: RegisterBank) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen, port))
        server.listen(5)
        while True:
            connection, _ = server.accept()
            threading.Thread(target=handle_client, args=(connection, bank), daemon=True).start()


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal Modbus/TCP PLC simulator.")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--state-file", default="/var/lib/ics-plc/state.json")
    args = parser.parse_args()

    bank = RegisterBank(Path(args.state_file))
    threading.Thread(target=bank.update_from_process, daemon=True).start()
    serve(args.listen, args.port, bank)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
