#!/usr/bin/env bash
set -euo pipefail

PROJECT="${PROJECT:-ICS-simulation}"
SCADA_API_URL="${SCADA_API_URL:-http://198.18.30.10:8081/api/tags}"
HMI_URL="${HMI_URL:-http://198.18.30.20:8080/}"

run_in_instance() {
  local instance="$1"
  local command="$2"
  incus exec --project "${PROJECT}" "${instance}" -- bash -lc "${command}"
}

pass() {
  printf '[PASS] %s\n' "$1"
}

fail() {
  printf '[FAIL] %s\n' "$1" >&2
  exit 1
}

require_success() {
  local message="$1"
  local instance="$2"
  local command="$3"

  if run_in_instance "${instance}" "${command}" >/dev/null 2>&1; then
    pass "${message}"
  else
    fail "${message}"
  fi
}

require_failure() {
  local message="$1"
  local instance="$2"
  local command="$3"

  if run_in_instance "${instance}" "${command}" >/dev/null 2>&1; then
    fail "${message}"
  else
    pass "${message}"
  fi
}

require_success "IT to DMZ SSH allowed" it-ws01 "nc -zvw3 198.18.20.10 22"
require_failure "IT to CELL blocked" it-ws01 "nc -zvw3 198.18.40.10 502"
require_success "OPS to CELL Modbus/TCP allowed" otops-scada01 "nc -zvw3 198.18.40.10 502"

MQTT_IP="$(incus list --project "${PROJECT}" mqtt01 -c 4 --format csv 2>/dev/null | head -n1 | awk '{print $1}' | cut -d',' -f1 || true)"
if [[ -n "${MQTT_IP}" ]]; then
  require_success "SCADA can reach MQTT broker" otops-scada01 "nc -zvw3 ${MQTT_IP} 1883"
else
  printf '[SKIP] MQTT smoke test skipped because mqtt01 is not deployed or has no detected IPv4 address\n'
fi

if curl -fsS "${SCADA_API_URL}" | grep -q '"tags"'; then
  pass "SCADA API returns tags"
else
  fail "SCADA API returns tags"
fi

if curl -fsS "${HMI_URL}" | grep -qi 'ICS HMI'; then
  pass "HMI page loads"
else
  fail "HMI page loads"
fi
