#!/usr/bin/env python3

import argparse
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCADA_API_URL = os.environ.get("SCADA_API_URL", "http://198.18.30.10:8081/api/tags")

HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ICS HMI</title>
  <style>
    :root {
      --bg: #0f1418;
      --panel: #1c252b;
      --text: #eef4f6;
      --muted: #9eb2bc;
      --accent: #e0b04b;
      --ok: #61c16f;
      --alarm: #d95d39;
    }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "DejaVu Sans", sans-serif;
      background:
        radial-gradient(circle at top right, rgba(224,176,75,0.18), transparent 32%),
        linear-gradient(180deg, #172027 0%, var(--bg) 100%);
      color: var(--text);
    }
    main {
      max-width: 960px;
      margin: 0 auto;
      padding: 2rem 1.25rem 3rem;
    }
    h1 {
      margin: 0 0 0.5rem;
      font-size: clamp(2rem, 6vw, 3.25rem);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    p {
      color: var(--muted);
      max-width: 48rem;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-top: 1.5rem;
    }
    .card {
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(0,0,0,0.18)), var(--panel);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 1rem;
      padding: 1rem;
      box-shadow: 0 16px 32px rgba(0,0,0,0.18);
    }
    .label {
      color: var(--muted);
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .value {
      font-size: 2rem;
      margin-top: 0.35rem;
      font-weight: 700;
    }
    .status-ok {
      color: var(--ok);
    }
    .status-alarm {
      color: var(--alarm);
    }
  </style>
</head>
<body>
  <main>
    <h1>ICS HMI</h1>
    <p>Live view of the simulated tank, driven by the SCADA poller in the OT operations zone.</p>
    <div class="grid" id="cards"></div>
  </main>
  <script>
    async function refresh() {
      const response = await fetch('/api/tags');
      const payload = await response.json();
      const tags = payload.tags || {};
      const entries = [
        ['Tank Level %', tags.tank_level_pct ?? 'n/a', false],
        ['Setpoint %', tags.setpoint_pct ?? 'n/a', false],
        ['Inlet Flow LPM', tags.inlet_flow_lpm ?? 'n/a', false],
        ['Outlet Flow LPM', tags.outlet_flow_lpm ?? 'n/a', false],
        ['Pump Running', tags.pump_running === 1 ? 'ON' : 'OFF', tags.pump_running === 1],
        ['High Alarm', tags.alarm_high === 1 ? 'ACTIVE' : 'CLEAR', tags.alarm_high === 1],
        ['Low Alarm', tags.alarm_low === 1 ? 'ACTIVE' : 'CLEAR', tags.alarm_low === 1],
        ['PLC Healthy', tags.plc_healthy === 1 ? 'YES' : 'NO', tags.plc_healthy === 1]
      ];

      const root = document.getElementById('cards');
      root.innerHTML = '';
      for (const [label, value, healthy] of entries) {
        const card = document.createElement('section');
        card.className = 'card';
        card.innerHTML = `<div class="label">${label}</div><div class="value ${healthy ? 'status-ok' : ''}">${value}</div>`;
        if ((label.includes('Alarm') && value === 'ACTIVE') || (label === 'PLC Healthy' && value === 'NO')) {
          card.querySelector('.value').classList.add('status-alarm');
          card.querySelector('.value').classList.remove('status-ok');
        }
        root.appendChild(card);
      }
    }

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"""


def fetch_tags() -> bytes:
    with urllib.request.urlopen(SCADA_API_URL, timeout=2) as response:
        return response.read()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/api/tags":
            body = fetch_tags()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple ICS HMI server.")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.listen, args.port), Handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
