#!/usr/bin/env bash
set -euo pipefail

PROJECT="${1:?usage: wait_for_cloud_init.sh <project> <instance>}"
INSTANCE="${2:?usage: wait_for_cloud_init.sh <project> <instance>}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-600}"
SLEEP_SECONDS="${SLEEP_SECONDS:-5}"

deadline=$((SECONDS + TIMEOUT_SECONDS))

while (( SECONDS < deadline )); do
  if incus exec --project "${PROJECT}" "${INSTANCE}" -- cloud-init status --wait >/dev/null 2>&1; then
    exit 0
  fi

  sleep "${SLEEP_SECONDS}"
done

echo "Timed out waiting for cloud-init on ${INSTANCE} in project ${PROJECT}" >&2
exit 1
