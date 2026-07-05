#include "hsm_interface.h"
#include "soft_file_hsm.h"
#include "constants.h"
#include "store.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <map>

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
        EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec) return ErrorCode::KEY_GENERATION_FAILED;
        if (!EC_KEY_generate_key(ec)) {
            EC_KEY_free(ec);
            return ErrorCode::KEY_GENERATION_FAILED;
        }

        const EC_GROUP* group = EC_KEY_get0_group(ec);
        const EC_POINT* pub = EC_KEY_get0_public_key(ec);
        size_t len = EC_POINT_point2oct(group, pub,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         nullptr, 0, nullptr);
        std::vector<uint8_t> raw_pub(len);
        EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                           raw_pub.data(), len, nullptr);

        const BIGNUM* priv = EC_KEY_get0_private_key(ec);
        int priv_len = BN_num_bytes(priv);
        std::vector<uint8_t> raw_priv(priv_len);
        BN_bn2bin(priv, raw_priv.data());

        EC_KEY_free(ec);

        key_pair.key_id = key_id;
        key_pair.algorithm = algorithm;
        key_pair.created_at = std::chrono::system_clock::now();
        key_pair.private_key_exists = true;
        key_pair.public_key = raw_pub;

        keys_[key_id] = {raw_pub, raw_priv};
        return ErrorCode::SUCCESS;
    }

    ErrorCode sign(const std::string& key_id,
                  const std::vector<uint8_t>& data,
                  std::vector<uint8_t>& signature) override {
        auto it = keys_.find(key_id);
        if (it == keys_.end()) {
            return ErrorCode::KEY_NOT_FOUND;
        }

        // Reconstruct EC_KEY for signing
        EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec) return ErrorCode::HSM_SIGN_FAILED;

        const EC_GROUP* group = EC_KEY_get0_group(ec);
        EC_POINT* pt = EC_POINT_new(group);
        if (!pt) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }
        EC_POINT_oct2point(group, pt, it->second.pub.data(),
                           it->second.pub.size(), nullptr);
        EC_KEY_set_public_key(ec, pt);
        EC_POINT_free(pt);

        BIGNUM* priv_bn = BN_bin2bn(it->second.priv.data(),
                                     static_cast<int>(it->second.priv.size()),
                                     nullptr);
        if (!priv_bn) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }
        EC_KEY_set_private_key(ec, priv_bn);
        BN_free(priv_bn);

        // SHA-256 hash the data first, then sign the digest.
        // ECDSA_sign does NOT hash internally — it signs the raw bytes passed.
        // OpenSSL's X509_REQ_verify does SHA256(TBS) then ECDSA_verify,
        // so we must match: hash first, then sign the 32-byte digest.
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256(data.data(), data.size(), digest);

        unsigned int sig_len = ECDSA_size(ec);
        signature.resize(sig_len);
        if (ECDSA_sign(0, digest, SHA256_DIGEST_LENGTH,
                       signature.data(), &sig_len, ec) != 1) {
            EC_KEY_free(ec);
            return ErrorCode::HSM_SIGN_FAILED;
        }
        signature.resize(sig_len);
        EC_KEY_free(ec);
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
        auto it = keys_.find(key_id);
        if (it == keys_.end()) {
            return ErrorCode::KEY_NOT_FOUND;
        }
        public_key = it->second.pub;
        return ErrorCode::SUCCESS;
    }

    bool key_exists(const std::string& key_id) override {
        return keys_.find(key_id) != keys_.end();
    }

    ErrorCode delete_key(const std::string& key_id) override {
        keys_.erase(key_id);
        return ErrorCode::SUCCESS;
    }

    std::string get_status() const override {
        return "Software HSM (Development)";
    }

private:
    std::string storage_path_;
    struct KeyData {
        std::vector<uint8_t> pub;
        std::vector<uint8_t> priv;
    };
    std::map<std::string, KeyData> keys_;
};

std::unique_ptr<HsmInterface> HsmFactory::create(HsmType type,
                                                 const std::string& config_path,
                                                 const std::string& store_root) {
    switch (type) {
        case HsmType::SOFTWARE:
            return std::make_unique<SoftwareHsm>(config_path);
        case HsmType::SOFT_FILE: {
            auto store = store_root.empty()
                ? hwyz::store::Store::open("sec")
                : hwyz::store::Store::open("sec", store_root);
            std::string enc_key_path = config_path.empty()
                ? std::string(DEFAULT_SOFT_KEY_PATH) + "/.encryption_key"
                : config_path + "/.encryption_key";
            return std::make_unique<SoftFileHsm>(
                std::move(store),
                DEFAULT_SOFT_KEY_ENC_ALGO,
                enc_key_path);
        }
        default:
            throw std::invalid_argument("Unsupported HSM type");
    }
}

} // namespace sec
} // namespace tbox
