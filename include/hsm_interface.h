#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include "error_codes.h"

namespace tbox {
namespace sec {

struct KeyPair {
    std::string key_id;
    std::string algorithm;
    std::vector<uint8_t> public_key;
    bool private_key_exists;
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
        SOFTWARE,
        PKCS11,
        TRUSTZONE
    };

    static std::unique_ptr<HsmInterface> create(HsmType type,
                                               const std::string& config_path = "");
};

} // namespace sec
} // namespace tbox
