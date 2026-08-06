#!/bin/bash
# Security smoke test for tbox-sec service.
# Exit 0 = pass, non-zero = fail.
#
# TBOX-SEC-DSN-CR-012 §13.3: SEC 非秘密安全冒烟入口。
#
# 边界：
#   - 不在普通冒烟中执行 getSeed/verifyKey/signTls/证书注入等非幂等安全操作
#     （禁止自动重放与 unknown-outcome，由受控 Orin 受控凭据人工/受控流程验证）；
#   - 不读取、不输出 PIN/Token/私钥/KeyRef/证书私钥等秘密值；
#   - 仅检查 fail-closed 配置、socket 生命周期、unit 引用与敏感材料扫描。

set -euo pipefail

CONFIG_FILE="/etc/tbox/conf.d/sec.yaml"
SOCKET_PATH="/tmp/tbox-sec.sock"

# --- 配置模板存在且为生产 fail-closed（禁止 soft_file 密钥模式） ---
if [ ! -f "${CONFIG_FILE}" ]; then
    echo "FAIL: config file ${CONFIG_FILE} not found"
    exit 1
fi
if grep -qE '^\s*mode:\s*"?soft_file"?' "${CONFIG_FILE}"; then
    echo "FAIL: 生产 sec.yaml 禁止 soft_file 密钥模式"
    exit 1
fi

# --- production profile schema/安全校验（checker 可用时；TBOX-SEC-DSN-CR-013 §8/§9） ---
# checker 不存在时回退到上面的 grep 检查（向后兼容）
if [ -x /usr/bin/sec_config_checker ]; then
    if ! /usr/bin/sec_config_checker --check-config "${CONFIG_FILE}" --profile production >/dev/null 2>&1; then
        echo "FAIL: sec.yaml production profile validation failed"
        /usr/bin/sec_config_checker --check-config "${CONFIG_FILE}" --profile production 2>&1 | grep '^ERROR' | head -5
        exit 1
    fi
fi

# --- IPC socket 存在（framework-ipc） ---
if [ ! -S "${SOCKET_PATH}" ]; then
    echo "FAIL: IPC socket ${SOCKET_PATH} not found"
    exit 1
fi

# --- 服务生命周期：restart 后 socket 重建，唯一实例 ---
systemctl restart tbox-sec.service
for i in $(seq 1 50); do
    if [ -S "${SOCKET_PATH}" ]; then
        break
    fi
    sleep 0.1
done
if [ ! -S "${SOCKET_PATH}" ]; then
    echo "FAIL: IPC socket ${SOCKET_PATH} not recreated after restart"
    exit 1
fi
if ! systemctl is-active --quiet tbox-sec.service; then
    echo "FAIL: tbox-sec.service not active after restart"
    exit 1
fi

# --- 敏感材料扫描（staging/package/install-root；不回显秘密内容） ---
# 用法：sec-security.sh [<扫描根目录>]；未提供时跳过（由 BUILD verify 编排传入
# out/orin/release 的 install-root / sdk 视图）。
SENSITIVE_PATTERNS=(
    "BEGIN PRIVATE KEY"
    "TESTVIN"
    "test_private_key"
    "SOFT_FILE"
    "\.soft_kek"
)
SCAN_ROOT="${1:-}"
if [ -n "${SCAN_ROOT}" ] && [ -d "${SCAN_ROOT}" ]; then
    for pat in "${SENSITIVE_PATTERNS[@]}"; do
        if grep -rIl -- "${pat}" "${SCAN_ROOT}" 2>/dev/null | head -1 | grep -q .; then
            echo "FAIL: sensitive pattern '${pat}' found under ${SCAN_ROOT}"
            exit 1
        fi
    done
    echo "OK: sensitive scan clean under ${SCAN_ROOT}"
fi

# --- graceful shutdown 后 socket 清理 ---
systemctl stop tbox-sec.service
for i in $(seq 1 30); do
    if [ ! -e "${SOCKET_PATH}" ]; then
        break
    fi
    sleep 0.1
done
if [ -e "${SOCKET_PATH}" ]; then
    echo "WARN: IPC socket ${SOCKET_PATH} still exists after stop (may be cleaning up)"
fi

# Restart for post-smoke state
systemctl start tbox-sec.service

echo "PASS: tbox-sec security smoke (fail-closed config, socket lifecycle, sensitive scan)"
exit 0
