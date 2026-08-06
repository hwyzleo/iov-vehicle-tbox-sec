#include "soft_file_hsm.h"
#include "constants.h"
#include "store.h"

#include <memory>
#include <stdexcept>
#include <string>

namespace tbox {
namespace sec {

// TBOX-SEC HSM 后端只分两类（不再有内存 mock）：
//   - 软件 HSM：SoftFileHsm —— 私钥经 AES-256-GCM + KEK 落盘持久化到 SEC 受控
//     存储，供无硬件 HSM 的车机（如 Orin）使用，重启后密钥存活。
//   - 硬件 HSM：PKCS#11 / TrustZone —— 由具体设备集成/部署注入 library_path。
//
// 说明：HsmType::SOFTWARE 保留为 SOFT_FILE 的兼容别名（等价于软件 HSM），
//       早期的内存 mock 实现（SoftwareHsm）已删除。
std::unique_ptr<HsmInterface> HsmFactory::create(HsmType type,
                                                 const std::string& config_path,
                                                 const std::string& store_root,
                                                 const std::string& enc_key_path) {
    switch (type) {
        case HsmType::SOFTWARE:   // 兼容别名 -> 软件 HSM（SoftFileHsm）
        case HsmType::SOFT_FILE: {
            // store 根：优先 store_root，其次 config_path（测试常只传一个路径），再退默认。
            const std::string root = !store_root.empty() ? store_root : config_path;
            auto store = root.empty()
                ? hwyz::store::Store::open("sec")
                : hwyz::store::Store::open("sec", root);
            // KEK 路径：优先显式传入（soft_key.encryption_key_path），
            // 为空则回退 {root|默认目录}/<默认KEK文件名>。
            const std::string kek_path = !enc_key_path.empty()
                ? enc_key_path
                : ((root.empty() ? std::string(DEFAULT_SOFT_KEY_PATH) : root)
                   + "/" + DEFAULT_SOFT_KEK_FILENAME);
            return std::make_unique<SoftFileHsm>(
                std::move(store),
                DEFAULT_SOFT_KEY_ENC_ALGO,
                kek_path);
        }
        case HsmType::PKCS11:
        case HsmType::TRUSTZONE:
            // 硬件 HSM 后端由具体设备集成提供；当前构建未链接厂商 SDK。
            throw std::invalid_argument("Hardware HSM backend not available in this build");
        default:
            throw std::invalid_argument("Unsupported HSM type");
    }
}

} // namespace sec
} // namespace tbox
