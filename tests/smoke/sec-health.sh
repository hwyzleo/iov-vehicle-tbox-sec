#!/bin/bash
# Health check for tbox-sec service.
# Exit 0 = healthy, non-zero = unhealthy.
#
# TBOX-SEC-DSN-CR-012 §13.3: SEC 特有健康检查入口（受控 Orin / CI 执行）。

set -euo pipefail

BIN_PATH="/usr/bin/tbox_sec"
SOCKET_PATH="/tmp/tbox-sec.sock"

# Check if the tbox_sec binary exists
if [ ! -x "${BIN_PATH}" ]; then
    echo "ERROR: tbox_sec binary not found at ${BIN_PATH}"
    exit 1
fi

# Check if the systemd service is active
if ! systemctl is-active --quiet tbox-sec.service; then
    echo "ERROR: tbox-sec.service is not active"
    exit 1
fi

# Check if the IPC socket exists (framework-ipc)
if [ ! -S "${SOCKET_PATH}" ]; then
    echo "ERROR: IPC socket ${SOCKET_PATH} not found"
    exit 1
fi

echo "OK: tbox-sec service is healthy (binary, service, socket)"
exit 0
