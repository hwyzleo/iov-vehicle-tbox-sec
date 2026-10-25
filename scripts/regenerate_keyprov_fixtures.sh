#!/bin/bash
#
# TBOX-SEC keyprov VEH-PROTO fixtures 再生 / 一致性校验（TBOX-SEC-DSN-CR-022 §5/§6）。
#
# 职责：
#   1. 运行本地 Python 再生工具（tests/fixtures/gen_keyprov_ecdh_es_v1_vector.py）
#      重新生成 keyprov_ecdh_es_v1_vector.json；
#   2. 用本地 protoc 生成 DescriptorSet 并计算 SHA-256；
#   3. 汇总生成 tests/fixtures/keyprov_fixture_manifest.json：
#       VEH-PROTO 文档修订、本地 proto source hash、本地 DescriptorSet hash、
#       protoc/plugin/runtime 版本、生成工具 hash 及每个向量文件 hash；
#   4. --check 模式：全部再生到临时目录并与 committed fixtures 逐字节比对，
#      同时校验 manifest 一致性；任一不一致退出码非 0（CI 门禁）。
#
# 用法：
#   scripts/regenerate_keyprov_fixtures.sh           # 再生并提交 fixtures + manifest
#   scripts/regenerate_keyprov_fixtures.sh --check   # 一致性校验（不修改任何文件）
#
# 说明：本工具是 SEC 仓库测试工具，仅按 VEH-PROTO 编码规则再生本地 fixtures；
# 不是协议 SSOT，也不得在量产运行时参与编码。
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES_DIR="$REPO_ROOT/tests/fixtures"
PROTO_FILE="proto/security/keyprov/v1/key_provisioning.proto"
TOOL="tests/fixtures/gen_keyprov_ecdh_es_v1_vector.py"
VECTOR_FILE="keyprov_ecdh_es_v1_vector.json"
MANIFEST_FILE="keyprov_fixture_manifest.json"
PROTOC="${PROTOC:-protoc}"
VEH_PROTO_REVISION="${VEH_PROTO_REVISION:-VEH-PROTO 2026-10-25（PAR-PROTO-DSN-CR-009 同步）}"

MODE="${1:-}"
CHECK_MODE=0
if [[ "$MODE" == "--check" ]]; then
  CHECK_MODE=1
elif [[ -n "$MODE" ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- 1. 再生 fixture JSON ----
python3 "$REPO_ROOT/$TOOL" --out "$tmp/$VECTOR_FILE"

# ---- 2. DescriptorSet ----
(cd "$REPO_ROOT" && "$PROTOC" \
  --descriptor_set_out="$tmp/descriptor.pb" \
  "$PROTO_FILE")

# ---- 3. hash 汇总 ----
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
sha256_bytes() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }

PROTO_HASH="$(sha256_file "$REPO_ROOT/$PROTO_FILE")"
DESCRIPTOR_HASH="$(sha256_file "$tmp/descriptor.pb")"
TOOL_HASH="$(sha256_file "$REPO_ROOT/$TOOL")"
VECTOR_HASH="$(sha256_file "$tmp/$VECTOR_FILE")"
VECTOR_BYTES="$(wc -c < "$tmp/$VECTOR_FILE" | tr -d ' ')"

PROTOC_VERSION="$("$PROTOC" --version | awk '{print $2}')"

# ---- 4. manifest ----
cat > "$tmp/$MANIFEST_FILE" <<EOF
{
  "veh_proto_revision": "$VEH_PROTO_REVISION",
  "par_proto_release": "PAR-PROTO-DSN-CR-009",
  "local_proto": {
    "file": "$PROTO_FILE",
    "sha256": "$PROTO_HASH"
  },
  "descriptor": {
    "sha256": "$DESCRIPTOR_HASH",
    "protoc_version": "$PROTOC_VERSION"
  },
  "generator_tool": {
    "file": "$TOOL",
    "sha256": "$TOOL_HASH"
  },
  "files": {
    "$VECTOR_FILE": {
      "sha256": "$VECTOR_HASH",
      "bytes": $VECTOR_BYTES
    }
  },
  "note": "任一项变化必须显式评审并重新生成；manifest 内容 hash 由 test_keyprov_proto_lock.cpp 锁定。"
}
EOF

# ---- 5. 比对 / 提交 ----
if [[ "$CHECK_MODE" -eq 1 ]]; then
  failures=0
  for f in "$VECTOR_FILE" "$MANIFEST_FILE"; do
    if ! cmp -s "$tmp/$f" "$FIXTURES_DIR/$f"; then
      echo "ERROR: $f differs from committed fixture" >&2
      failures=1
    fi
  done
  # manifest 记录 hash 与真实文件一致
  manifest_vec_hash="$(python3 -c "import json;print(json.load(open('$tmp/$MANIFEST_FILE'))['files']['$VECTOR_FILE']['sha256'])")"
  if [[ "$manifest_vec_hash" != "$VECTOR_HASH" ]]; then
    echo "ERROR: manifest vector hash mismatch" >&2
    failures=1
  fi
  if [[ "$failures" -ne 0 ]]; then
    echo "FAIL: fixtures 与 regenerated 不一致（CI 门禁）" >&2
    exit 1
  fi
  echo "OK: fixtures 与 regenerated 逐字节一致（--check 通过）"
else
  cp "$tmp/$VECTOR_FILE" "$FIXTURES_DIR/$VECTOR_FILE"
  cp "$tmp/$MANIFEST_FILE" "$FIXTURES_DIR/$MANIFEST_FILE"
  echo "wrote $FIXTURES_DIR/$VECTOR_FILE ($VECTOR_BYTES bytes)"
  echo "wrote $FIXTURES_DIR/$MANIFEST_FILE"
  echo "  veh_proto_revision : $VEH_PROTO_REVISION"
  echo "  proto sha256       : $PROTO_HASH"
  echo "  descriptor sha256  : $DESCRIPTOR_HASH (protoc $PROTOC_VERSION)"
  echo "  tool sha256        : $TOOL_HASH"
  echo "  vector sha256      : $VECTOR_HASH"
fi
