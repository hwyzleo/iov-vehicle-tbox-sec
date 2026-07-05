#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include "error_codes.h"

namespace tbox {
namespace sec {

enum class KeyStorageMode {
    HSM,        // HSM/SE 模式，私钥不出件（量产默认）
    SOFT_FILE   // 软件落盘模式，私钥加密存储到磁盘（仅测试）
};

struct KeyPair {
    std::string key_id;
    std::string algorithm;
    std::vector<uint8_t> public_key;
    bool private_key_exists;
    KeyStorageMode storage_mode = KeyStorageMode::HSM;  // 新增：存储模式
    bool exportable = false;                             // 新增：是否可导出
    std::chrono::system_clock::time_point created_at;
};

class HsmInterface {
public:
    virtual ~HsmInterface() = default;

    virtual ErrorCode initialize() = 0;

    virtual ErrorCode generate_key_pair(const std::string& key_id,
                                       const std::string& algorithm,
                                       KeyPair& key_pair) = 0;

    virtual ErrorCode sign(const std::string& key_id,
                          const std::vector<uint8_t>& data,
                          std::vector<uint8_t>& signature) = 0;

    virtual ErrorCode verify(const std::string& key_id,
                            const std::vector<uint8_t>& data,
                            const std::vector<uint8_t>& signature,
                            bool& valid) = 0;

    virtual ErrorCode export_public_key(const std::string& key_id,
                                       std::vector<uint8_t>& public_key) = 0;

    virtual bool key_exists(const std::string& key_id) = 0;

    virtual ErrorCode delete_key(const std::string& key_id) = 0;

    virtual std::string get_status() const = 0;
};

class HsmFactory {
public:
    enum class HsmType {
        SOFTWARE,    // 内存中的软件 HSM
        SOFT_FILE,   // 软件落盘 HSM（新增）
        PKCS11,      // PKCS#11 HSM
        TRUSTZONE    // TrustZone HSM
    };

    static std::unique_ptr<HsmInterface> create(HsmType type,
                                               const std::string& config_path = "",
                                               const std::string& store_root = "");
};

} // namespace sec
} // namespace tbox
