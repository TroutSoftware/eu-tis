#!/usr/bin/env sh
set -eu

if command -v ip >/dev/null 2>&1; then
  if [ -n "${OCI_STATIC_IP:-}" ]; then
    ip addr add "${OCI_STATIC_IP}" dev eth0 || true
  fi

  if [ -n "${OCI_GATEWAY:-}" ]; then
    ip route replace default via "${OCI_GATEWAY}" || true
  fi
fi

exec "$@"
