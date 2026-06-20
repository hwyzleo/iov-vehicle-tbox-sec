# TBOX Security Service 快速部署参考卡

## 一键部署命令

```bash
# 1. 编译（选择一种方式）

# 方式A: 本地编译（开发测试）
./scripts/build-local.sh

# 方式B: Docker交叉编译（部署到TBOX）
docker build -f Dockerfile.cross -t tbox-sec .
docker run --rm -v $(pwd)/output:/dest tbox-sec

# 方式C: 直接交叉编译
mkdir build-aarch64 && cd build-aarch64
cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain-aarch64-linux-gnu.cmake
make -j$(nproc)

# 2. 部署到TBOX
./scripts/deploy.sh <TBOX_IP> root

# 3. 配置TBOX
ssh root@<TBOX_IP> "vi /opt/tbox-sec/config/config.yaml"

# 4. 启动服务
ssh root@<TBOX_IP> "systemctl start tbox-sec"

# 5. 验证
ssh root@<TBOX_IP> "systemctl status tbox-sec"
ssh root@<TBOX_IP> "journalctl -u tbox-sec -f"
```

## 目录结构（TBOX上）

```
/opt/tbox-sec/
├── TboxSecService          # 主程序
├── config/
│   └── config.yaml         # 配置文件
└── lib/                    # 依赖库（如需要）

/var/lib/tbox/sec/
├── keys/                   # 密钥存储
├── certs/                  # 证书存储
└── provision_state.json    # 状态文件

/var/log/tbox/
└── sec_service.log         # 日志文件
```

## 配置文件模板

```yaml
tbox:
  vin: "实际VIN"              # 必须修改
  ecu_uid: "实际ECU_UID"      # 必须修改
  
  hsm:
    type: "pkcs11"            # 生产环境用pkcs11
    library_path: "/usr/lib/softhsm2/libsofthsm2.so"
    
  cloud:
    oapi_endpoint: "https://实际地址:10805"  # 必须修改
    
  storage:
    state_file: "/var/lib/tbox/sec/provision_state.json"
```

## 诊断仪测试命令

```
# 读取Provision状态
22 F1 00

# 安全访问
29 29           # 请求种子
29 2A <密钥>    # 发送密钥

# 生成密钥对
31 01 FF 00

# 读取CSR
22 F1 01

# 写入证书
2E F1 02 <证书数据>
```

## 常见问题速查

| 问题 | 命令 |
|------|------|
| 查看日志 | `journalctl -u tbox-sec -f` |
| 重启服务 | `systemctl restart tbox-sec` |
| 检查依赖 | `ldd /opt/tbox-sec/TboxSecService` |
| 手动运行 | `/opt/tbox-sec/TboxSecService /opt/tbox-sec/config/config.yaml` |
| 检查端口 | `netstat -tlnp \| grep TboxSecService` |

## 文件清单

```
scripts/
├── deploy.sh           # 自动部署脚本
├── build-local.sh      # 本地编译脚本
└── setup-dev.sh        # 开发环境配置

toolchain-aarch64-linux-gnu.cmake  # 交叉编译工具链
Dockerfile.cross                    # Docker交叉编译
docs/deployment.md                  # 完整部署文档
```
