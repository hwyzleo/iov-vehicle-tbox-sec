#pragma once

#include "hsm_interface.h"
#include <string>
#include <map>
#include <mutex>

namespace tbox {
namespace sec {

class SoftFileHsm : public HsmInterface {
public:
    SoftFileHsm(const std::string& key_store_path,
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
                                 std::vector<uint8_t>& private_key);

private:
    std::string key_store_path_;
    std::string encryption_algo_;
    std::string encryption_key_path_;
    std::vector<uint8_t> encryption_key_;

    struct KeyData {
        std::vector<uint8_t> pub;
        std::vector<uint8_t> priv;
        std::string algorithm;
        std::chrono::system_clock::time_point created_at;
        bool priv_encrypted_on_disk = false;
    };
    std::map<std::string, KeyData> keys_;
    std::mutex mutex_;

    ErrorCode load_key_from_disk(const std::string& key_id, KeyData& key_data);
    ErrorCode save_key_to_disk(const std::string& key_id, const KeyData& key_data);
    ErrorCode encrypt_private_key(const std::vector<uint8_t>& plain_key,
                                  std::vector<uint8_t>& encrypted_key);
    ErrorCode decrypt_private_key(const std::vector<uint8_t>& encrypted_key,
                                  std::vector<uint8_t>& plain_key);
    std::string get_key_file_path(const std::string& key_id);
    std::string get_key_dot_key_path(const std::string& key_id);
    ErrorCode generate_encryption_key();
    ErrorCode load_encryption_key();
    void secure_zero(std::vector<uint8_t>& data);
};

} // namespace sec
} // namespace tbox
