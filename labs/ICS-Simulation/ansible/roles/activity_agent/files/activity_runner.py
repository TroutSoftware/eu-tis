#!/usr/bin/env python3

import argparse
import http.client
import socket
import sys
import time
from pathlib import Path

import yaml


def tcp_check(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def http_get(url: str, timeout: float) -> bool:
    if not url.startswith("http://"):
        raise ValueError(f"Only plain HTTP URLs are supported by the sample runner: {url}")

    without_scheme = url[len("http://") :]
    host_port, _, path = without_scheme.partition("/")
    if ":" in host_port:
        host, port_text = host_port.split(":", 1)
        port = int(port_text)
    else:
        host = host_port
        port = 80

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", "/" + path)
        response = conn.getresponse()
        return 200 <= response.status < 400
    finally:
        conn.close()


def run_step(step: dict, timeout: float) -> bool:
    action = step["action"]
    name = step.get("name", action)

    if action == "sleep":
        seconds = float(step.get("seconds", 1))
        print(f"[INFO] {name}: sleeping for {seconds} seconds")
        time.sleep(seconds)
        return True

    if action == "tcp_check":
        is_open = tcp_check(step["host"], int(step["port"]), timeout)
        expect = step.get("expect", "open")
        expected_open = expect == "open"
        print(f"[INFO] {name}: tcp {step['host']}:{step['port']} open={is_open} expected={expect}")
        return is_open == expected_open

    if action == "http_get":
        ok = http_get(step["url"], timeout)
        print(f"[INFO] {name}: http_get {step['url']} ok={ok}")
        return ok

    raise ValueError(f"Unsupported action {action}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a simple ICS lab activity scenario.")
    parser.add_argument(
        "--scenario",
        default="/opt/ics/activity/scenario.yaml",
        help="Path to the YAML scenario file.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Network timeout in seconds for active checks.",
    )
    args = parser.parse_args()

    scenario_path = Path(args.scenario)
    payload = yaml.safe_load(scenario_path.read_text()) or {}
    steps = payload.get("steps", [])

    for step in steps:
        if not run_step(step, args.timeout):
            print(f"[ERROR] Scenario step failed: {step.get('name', step.get('action'))}", file=sys.stderr)
            return 1

    print("[INFO] Scenario completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
