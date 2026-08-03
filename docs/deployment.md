# TBOX Security Service 构建与部署（TBOX-SEC-DSN-CR-012）

> 基线：CR-012 起，SEC 的 Orin 交叉构建、打包、部署、验证与回退统一由
> TBOX-BUILD 仓库编排；本仓库只维护 HOST 开发构建与服务侧交付物。

## 1. 构建入口

### 1.1 HOST 开发构建（本仓库）

```bash
./scripts/setup-dev.sh     # 安装 HOST 依赖（Homebrew + Conan）
./scripts/build.sh         # conan install + configure + build + ctest
```

前置：framework（FW CR-010）与 PROV（PROV CR-009）的 SDK package 已安装到
`${TBOX_PREFIX}`（默认 `~/.local`），由 `iov-vehicle-tbox-framework/scripts/tbox-env.sh`
提供 `TBOX_PREFIX` / `TBoxFramework_DIR`。

### 1.2 Orin 正式构建（TBOX-BUILD）

```bash
cd ../iov-vehicle-tbox-build
./ci/build-in-docker.sh    # 或 python3 -m tbox_build build --platform orin --profile release --set tbox-sec-orin
```

- release-set：`tbox-sec-orin`（framework + PROV + SEC）
- SEC 不维护独立交叉编译脚本/toolchain/sysroot/容器入口（CR-012 §6.1）

## 2. Install Components 与 Staging

| component | staging | 内容 |
|---|---|---|
| `sec-sdk` | sdk | `include/tbox/sec/`、`libtbox_sec_client.a`、`lib/cmake/TboxSecClient/` |
| `sec-runtime` | rootfs | `bin/tbox_sec`、`lib/systemd/system/tbox-sec.service`、`etc/tbox/conf.d/sec.yaml` |

```bash
# 本地双 staging 验证
cmake --install build --prefix /usr --component sec-sdk --destdir "$PWD/build/stage/sdk"
cmake --install build --prefix /usr --component sec-runtime --destdir "$PWD/build/stage/rootfs"
./scripts/verify-artifacts.sh
```

量产 rootfs 不安装开发头文件、静态库、CMake package、测试证书或 HSM 模拟器资产。

## 3. 配置

- 公共层：`/etc/tbox/common.yaml`（framework-config；由 BUILD/首个服务安装）
- 服务层：`/etc/tbox/conf.d/sec.yaml`（本仓库安装 `config/sec.default.yaml` 重命名而来，非秘密默认模板）
- 设备本地覆盖：工作目录 `./config/sec.yaml` 或 `CONFIG_FILE`（最高优先级）

生产默认模板要点（fail-closed）：
- `key_provisioning.mode: hsm`；量产禁止 `soft_file`（代码拒绝 `SOFT_KEY_MODE_NOT_ALLOWED`）
- 不含 `dev_peer_service`、测试端点、测试密钥
- `hsm.type` / `library_path` / `cloud.endpoint` 由部署注入（非秘密）
- `environment.is_production: true`（部署可覆盖）

开发/测试使用仓库 `config/sec.yaml`（soft_file 等测试值，不进入量产制品）。

## 4. 运行与验证（受控 Orin）

```bash
systemctl start tbox-sec.service
# 依赖顺序：framework（无 unit）-> tbox-prov.service -> tbox-sec.service（after 登记）
```

- health：`tests/smoke/sec-health.sh`（binary / service / socket）
- security smoke：`tests/smoke/sec-security.sh`（fail-closed 配置、socket 生命周期、
  敏感材料扫描；不在普通冒烟执行非幂等安全操作）
- 完整 Orin 最小安全验证（HSM session、Seed-Key、CSR/证书、MQTT TLS、graceful
  shutdown、release-set 回退）由受控 Orin 环境按 CR-012 §13.3 执行

## 5. 故障排查

| 问题 | 原因 | 解决方案 |
|---|---|---|
| 启动即退出 | PROV 未就绪（IpcProvService 连接失败） | 先启动 tbox-prov.service |
| `sec.config.hsm_type_required` | hsm.type 未配置 | 按部署注入 pkcs11/trustzone |
| `sec.hsm.soft_file_production_denied` | 量产使用 soft_file | 切换 key_provisioning.mode: hsm |
| 链接缺 PROV 符号 | 消费方未走已安装 package | find_package(TboxProvClient) + tbox::prov_client |
