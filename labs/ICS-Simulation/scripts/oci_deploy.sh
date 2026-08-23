#!/usr/bin/env bash
set -euo pipefail

PROJECT="ICS-simulation"
REMOTE_NAME="oci-docker"

ensure_remote() {
  if ! incus remote list --format csv | awk -F, '{print $1}' | grep -qx "${REMOTE_NAME}"; then
    incus remote add "${REMOTE_NAME}" https://docker.io --protocol=oci
  fi
}

launch_if_missing() {
  local image="$1"
  local name="$2"
  local network="$3"

  if incus info --project "${PROJECT}" "${name}" >/dev/null 2>&1; then
    echo "Skipping ${name}: already present"
    return
  fi

  incus launch --project "${PROJECT}" --network "${network}" "${image}" "${name}"
}

ensure_remote

launch_if_missing "${REMOTE_NAME}:eclipse-mosquitto" mqtt01 ics-ot-dmz

if [[ "${DEPLOY_OBSERVABILITY:-0}" == "1" ]]; then
  launch_if_missing "${REMOTE_NAME}:influxdb:2.7" influxdb01 ics-ot-ops
  launch_if_missing "${REMOTE_NAME}:grafana/grafana" grafana01 ics-ot-ops
fi

cat <<'EOF'
OCI deployment attempted.

Note:
- `mqtt01` is attached to `ics-ot-dmz`.
- Optional `influxdb01` and `grafana01` are attached to `ics-ot-ops` when `DEPLOY_OBSERVABILITY=1`.
- OCI app containers can require manual network bootstrap when attached to bridges without DHCP.
- See `scripts/oci-wrapper.sh` and the top-level README for an `oci.entrypoint` wrapper pattern.
EOF
