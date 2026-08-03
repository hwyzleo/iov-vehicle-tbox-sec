//
// TBOX-SEC-DSN-CR-012 §13.1: installed-package consumer。
// 仅做编译期/链接期验证：构造 SecClient、检查 facade API 可解析、
// 验证错误码与状态类型来自安装后的公共头文件（tbox/sec/...）。
// 不连接真实 daemon、不执行任何安全操作。
//

#include <tbox/sec/client.h>
#include <tbox/sec/errors.h>
#include <tbox/sec/types.h>

#include <cstdio>
#include <vector>

int main() {
    // 构造（默认 socket 路径）——验证公开构造可用
    tbox::sec::SecClient client("/tmp/tbox-sec-consumer.sock");

    // 公开类型可解析
    tbox::sec::ErrorCode ec = tbox::sec::ErrorCode::SUCCESS;
    if (ec != tbox::sec::ErrorCode::SUCCESS) {
        return 1;
    }

    // facade 方法可调用（仅声明；不连接 daemon）
    client.disconnect();

    // DTO 类型可实例化
    tbox::sec::TlsCredentialState state;
    (void)state;

    std::printf("OK: tbox::sec_client installed-package consumer compiles/links\n");
    return 0;
}
