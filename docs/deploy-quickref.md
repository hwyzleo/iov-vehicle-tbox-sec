# TBOX Security Service 快速参考卡（TBOX-SEC-DSN-CR-012）

## 构建

```bash
# HOST 开发构建（本仓库）
./scripts/build.sh

# Orin 正式构建（TBOX-BUILD 统一编排，tbox-sec-orin release-set）
cd ../iov-vehicle-tbox-build
./ci/build-in-docker.sh
```

## 本地双 staging 与静态验证

```bash
cmake --install build --prefix /usr --component sec-sdk --destdir "$PWD/build/stage/sdk"
cmake --install build --prefix /usr --component sec-runtime --destdir "$PWD/build/stage/rootfs"
./scripts/verify-artifacts.sh
```

## Installed-package Consumer

```bash
cmake -S tests/consumer -B build-consumer --toolchain "$PWD/build/conan_toolchain.cmake" \
  -DTboxSecClient_DIR="$PWD/build/stage/sdk/usr/lib/cmake/TboxSecClient" \
  -DTBoxFramework_DIR="$HOME/.local/lib/cmake/TboxFramework"
cmake --build build-consumer && ./build-consumer/sec_consumer
```

## 受控 Orin 冒烟

```bash
systemctl start tbox-sec.service
/usr/lib/tbox/tests/smoke/sec-health.sh      # binary / service / socket
/usr/lib/tbox/tests/smoke/sec-security.sh    # fail-closed 配置 / socket 生命周期 / 敏感扫描
```

## 目录结构（目标设备）

```
/etc/tbox/
├── common.yaml             # 公共配置（framework-config 公共层）
└── conf.d/
    └── sec.yaml            # SEC 服务层（非秘密默认模板，源自 config/sec.default.yaml）

/var/tbox/sec/              # framework-store 非秘密状态（persistent_paths 登记）
/var/log/tbox/              # framework-log 日志
```

## 配置要点（生产 fail-closed）

```yaml
# /etc/tbox/conf.d/sec.yaml（生产模板默认）
key_provisioning:
  mode: "hsm"               # 量产禁止 soft_file
environment:
  is_production: true
# hsm.type / library_path / cloud.endpoint 由部署注入（非秘密）
```

## 常见问题

| 问题 | 原因 | 解决 |
|---|---|---|
| 启动即退出 | PROV 未就绪 | 先启动 tbox-prov.service（after 已登记） |
| `sec.config.hsm_type_required` | hsm.type 未配置 | 注入 pkcs11/trustzone 与 library_path |
| `sec.hsm.soft_file_production_denied` | 量产 soft_file | 改 key_provisioning.mode: hsm |
| 日志 | - | `journalctl -u tbox-sec -f` |

## 服务侧文件清单

```
CMakeLists.txt                      # find_package(TboxFramework/TboxProvClient) + 双 components
cmake/TboxSecClientConfig.cmake.in  # 可重定位 package config（+ Version）
packaging/systemd/tbox-sec.service  # systemd unit（sec-runtime 安装）
config/sec.default.yaml             # 非秘密生产默认模板（安装为 sec.yaml）
config/sec.yaml                     # 开发/测试配置（不安装）
tests/smoke/sec-health.sh           # health 入口（BUILD metadata 引用）
tests/smoke/sec-security.sh         # security smoke 入口
tests/consumer/                     # installed-package consumer
scripts/verify-artifacts.sh         # HOST 静态制品验证
```

详细文档见 `docs/deployment.md`；Orin 部署/回退编排见 TBOX-BUILD 仓库。
