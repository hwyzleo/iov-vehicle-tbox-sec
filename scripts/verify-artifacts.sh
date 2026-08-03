#!/bin/bash
# TBOX-SEC-DSN-CR-012 §10/§11: 本地静态制品验证入口（HOST 开发用）。
#
# 对 SEC daemon / client 静态库执行 ELF/ABI/依赖/宿主污染/敏感材料检查。
# BUILD 侧 Orin 交叉制品的完整验证由 tbox-build 编排（ELF64/AArch64、
# interpreter、NEEDED、SONAME、RPATH、Manifest），本脚本用于 HOST 产物
# 的快速回归与敏感材料门禁。
#
# 用法: ./scripts/verify-artifacts.sh [<构建目录>] [<sdk stage>] [<rootfs stage>]
#   默认构建目录: build/；默认 sdk stage: build/stage/sdk/usr；
#   默认 rootfs stage: build/stage/rootfs/usr
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${PROJECT_ROOT}/build}"
SDK_STAGE="${2:-${BUILD_DIR}/stage/sdk/usr}"
ROOTFS_STAGE="${3:-${BUILD_DIR}/stage/rootfs/usr}"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

echo "=== [1/4] 制品存在性 ==="
for f in "${BUILD_DIR}/tbox_sec" "${BUILD_DIR}/libtbox_sec_client.a"; do
    [ -f "$f" ] || fail "missing artifact: $f"
    echo "OK: $f"
done

echo ""
echo "=== [2/4] ELF/架构/污染检查（daemon） ==="
BIN="${BUILD_DIR}/tbox_sec"
ARCH=$(file -b "$BIN" | grep -oE "(x86-64|aarch64|arm64|Mach-O)" | head -1 || true)
echo "  架构: ${ARCH}"
# HOST 开发产物为 Mach-O/x86-64 属正常（CR-012 §1：Apple Silicon Mac Docker
# 仅用于开发验证，不得作为唯一发布证据）；Orin 交叉制品的 ELF64/AArch64
# 与宿主污染检查由 BUILD 编排（§10）。此处仅对 RPATH 宿主路径做门禁。
case "$ARCH" in
    *Mach-O*|*x86-64*)
        echo "  NOTE: HOST 开发产物（${ARCH}）；Orin ELF64/AArch64 验证由 tbox-build 编排"
        ;;
esac

# RPATH / RUNPATH 不得包含宿主绝对路径或 build-tree 路径
if command -v readelf >/dev/null 2>&1; then
    RPATH=$(readelf -d "$BIN" 2>/dev/null | grep -E "RPATH|RUNPATH" || true)
    echo "  动态路径: ${RPATH:-<none>}"
    if echo "$RPATH" | grep -qE "${HOME}|/usr/local|/Users/|/build/"; then
        fail "RPATH/RUNPATH 含宿主/个人/build-tree 路径"
    fi
fi

echo ""
echo "=== [3/4] 敏感材料扫描（量产 staging 视图；HOST 单测日志不属发布制品） ==="
SENSITIVE_PATTERNS=(
    "BEGIN PRIVATE KEY"
    "TESTVIN"
    "test_private_key"
    "SOFT_FILE"
    "\.soft_kek"
)
for dir in "${SDK_STAGE}" "${ROOTFS_STAGE}"; do
    [ -d "$dir" ] || continue
    for pat in "${SENSITIVE_PATTERNS[@]}"; do
        if grep -rIl -- "$pat" "$dir" 2>/dev/null | head -1 | grep -q .; then
            fail "sensitive pattern '$pat' found under $dir"
        fi
    done
    echo "OK: 敏感扫描通过: $dir"
done

echo ""
echo "=== [4/4] install 视图检查（sec-sdk / sec-runtime 路由） ==="
if [ -d "${SDK_STAGE}" ] && [ -d "${ROOTFS_STAGE}" ]; then
    [ -f "${SDK_STAGE}/include/tbox/sec/client.h" ] \
        || fail "sec-sdk 缺公共头文件"
    [ -f "${SDK_STAGE}/lib/libtbox_sec_client.a" ] \
        || fail "sec-sdk 缺 client 静态库"
    [ -f "${SDK_STAGE}/lib/cmake/TboxSecClient/TboxSecClientConfig.cmake" ] \
        || fail "sec-sdk 缺 CMake package"
    [ -f "${SDK_STAGE}/lib/cmake/TboxSecClient/TboxSecClientConfigVersion.cmake" ] \
        || fail "sec-sdk 缺 CMake Version 文件"
    [ -f "${ROOTFS_STAGE}/bin/tbox_sec" ] \
        || fail "sec-runtime 缺 daemon"
    [ -f "${ROOTFS_STAGE}/lib/systemd/system/tbox-sec.service" ] \
        || fail "sec-runtime 缺 systemd unit"
    [ -f "${ROOTFS_STAGE}/etc/tbox/conf.d/sec.yaml" ] \
        || fail "sec-runtime 缺默认配置模板"
    echo "OK: sec-sdk/sec-runtime 文件路由完整"
else
    echo "SKIP: 未找到 sdk/rootfs stage（先执行 cmake --install 到 stage）"
fi

echo ""
echo "PASS: SEC 静态制品验证完成"
exit 0
