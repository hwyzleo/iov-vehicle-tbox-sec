#include "hsm_interface.h"
#include <stdexcept>

namespace tbox {
namespace sec {

class SoftwareHsm : public HsmInterface {
public:
    SoftwareHsm(const std::string& storage_path) : storage_path_(storage_path) {}

    ErrorCode initialize() override {
        return ErrorCode::SUCCESS;
    }

    ErrorCode generate_key_pair(const std::string& key_id,
                               const std::string& algorithm,
                               KeyPair& key_pair) override {
        key_pair.key_id = key_id;
        key_pair.algorithm = algorithm;
        key_pair.created_at = std::chrono::system_clock::now();
        key_pair.private_key_exists = true;
        key_pair.public_key = {0x04, 0x01, 0x02, 0x03};
        return ErrorCode::SUCCESS;
    }

    ErrorCode sign(const std::string& key_id,
                  const std::vector<uint8_t>& data,
                  std::vector<uint8_t>& signature) override {
        signature = {0x30, 0x06, 0x01, 0x02, 0x03, 0x04};
        return ErrorCode::SUCCESS;
    }

    ErrorCode verify(const std::string& key_id,
                    const std::vector<uint8_t>& data,
                    const std::vector<uint8_t>& signature,
                    bool& valid) override {
        valid = true;
        return ErrorCode::SUCCESS;
    }

    ErrorCode export_public_key(const std::string& key_id,
                               std::vector<uint8_t>& public_key) override {
        public_key = {0x04, 0x01, 0x02, 0x03};
        return ErrorCode::SUCCESS;
    }

    bool key_exists(const std::string& key_id) override {
        return true;
    }

    ErrorCode delete_key(const std::string& key_id) override {
        return ErrorCode::SUCCESS;
    }

    std::string get_status() const override {
        return "Software HSM (Development)";
    }

private:
    std::string storage_path_;
};

std::unique_ptr<HsmInterface> HsmFactory::create(HsmType type,
                                                 const std::string& config_path) {
    switch (type) {
        case HsmType::SOFTWARE:
            return std::make_unique<SoftwareHsm>(config_path);
        default:
            throw std::invalid_argument("Unsupported HSM type");
    }
}

} // namespace sec
} // namespace tbox
