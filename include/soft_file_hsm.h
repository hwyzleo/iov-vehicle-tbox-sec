#pragma once

#include "hsm_interface.h"
#include "store.h"

#include <string>
#include <vector>
#include <mutex>
#include <map>

namespace tbox {
namespace sec {

class SoftFileHsm : public HsmInterface {
public:
    SoftFileHsm(hwyz::store::Store store,
                const std::string& encryption_algo,
                const std::string& encryption_key_path);
    ~SoftFileHsm() override;

    ErrorCode initialize() override;

    ErrorCode generate_key_pair(const std::string& key_id,
                                const std::string& algorithm,
                                KeyPair& key_pair) override;

    ErrorCode sign(const std::string& key_id,
                   const std::vector<uint8_t>& data,
                   std::vector<uint8_t>& signature) override;

    ErrorCode verify(const std::string& key_id,
                     const std::vector<uint8_t>& data,
                     const std::vector<uint8_t>& signature,
                     bool& valid) override;

    ErrorCode export_public_key(const std::string& key_id,
                                std::vector<uint8_t>& public_key) override;

    bool key_exists(const std::string& key_id) override;

    ErrorCode delete_key(const std::string& key_id) override;

    std::string get_status() const override;

    ErrorCode export_private_key(const std::string& key_id,
                                 std::vector<uint8_t>& private_key) override;

private:
    hwyz::store::Store store_;
    std::string encryption_algo_;
    std::string encryption_key_path_;
    std::vector<uint8_t> encryption_key_;

    struct KeyData {
        std::vector<uint8_t> pub;
        std::vector<uint8_t> priv;
        std::string algorithm;
        std::chrono::system_clock::time_point created_at;
    };
    std::map<std::string, KeyData> keys_;
    mutable std::mutex mutex_;

    bool is_valid_key_id(const std::string& key_id) const;
    ErrorCode save_key_to_store(const std::string& key_id, const KeyData& key_data);
    ErrorCode load_key_from_store(const std::string& key_id, KeyData& key_data);
    ErrorCode encrypt_private_key(const std::vector<uint8_t>& plain_key,
                                  std::vector<uint8_t>& encrypted_key);
    ErrorCode decrypt_private_key(const std::vector<uint8_t>& encrypted_key,
                                  std::vector<uint8_t>& plain_key);
    ErrorCode generate_encryption_key();
    ErrorCode load_encryption_key();
    void secure_zero(std::vector<uint8_t>& data);

    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
};

} // namespace sec
} // namespace tbox
