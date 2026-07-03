#include "soft_file_hsm.h"
#include "constants.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <chrono>
#include <cstring>
#include <iostream>

namespace tbox {
namespace sec {

namespace fs = std::filesystem;

static constexpr int AES_GCM_IV_SIZE = 12;
static constexpr int AES_GCM_TAG_SIZE = 16;
static constexpr int ENCRYPTION_KEY_SIZE = 32;

SoftFileHsm::SoftFileHsm(hwyz::store::Store store,
                         const std::string& encryption_algo,
                         const std::string& encryption_key_path)
    : store_(std::move(store)),
      encryption_algo_(encryption_algo),
      encryption_key_path_(encryption_key_path) {}

SoftFileHsm::~SoftFileHsm() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, kd] : keys_) {
        secure_zero(kd.priv);
    }
    secure_zero(encryption_key_);
}

ErrorCode SoftFileHsm::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (fs::exists(encryption_key_path_)) {
        auto rc = load_encryption_key();
        if (rc != ErrorCode::SUCCESS) return rc;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::generate_key_pair(const std::string& key_id,
                                         const std::string& algorithm,
                                         KeyPair& key_pair) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    if (keys_.find(key_id) != keys_.end()) {
        return ErrorCode::KEY_ALREADY_EXISTS;
    }

    KeyData kd;
    kd.algorithm = algorithm;
    kd.created_at = std::chrono::system_clock::now();

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::KEY_GENERATION_FAILED;

    if (!EC_KEY_generate_key(ec)) {
        EC_KEY_free(ec);
        return ErrorCode::KEY_GENERATION_FAILED;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    const EC_POINT* pub = EC_KEY_get0_public_key(ec);
    size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    kd.pub.resize(len);
    EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, kd.pub.data(), len, nullptr);

    const BIGNUM* priv = EC_KEY_get0_private_key(ec);
    int priv_len = BN_num_bytes(priv);
    kd.priv.resize(priv_len);
    BN_bn2bin(priv, kd.priv.data());

    EC_KEY_free(ec);

    auto rc = save_key_to_store(key_id, kd);
    if (rc != ErrorCode::SUCCESS) {
        secure_zero(kd.priv);
        return rc;
    }

    key_pair.key_id = key_id;
    key_pair.algorithm = algorithm;
    key_pair.public_key = kd.pub;
    key_pair.private_key_exists = true;
    key_pair.storage_mode = KeyStorageMode::SOFT_FILE;
    key_pair.exportable = true;
    key_pair.created_at = kd.created_at;

    keys_[key_id] = std::move(kd);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::sign(const std::string& key_id,
                            const std::vector<uint8_t>& data,
                            std::vector<uint8_t>& signature) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::HSM_SIGN_FAILED;

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (!pt) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }
    if (EC_POINT_oct2point(group, pt, it->second.pub.data(), it->second.pub.size(), nullptr) != 1) {
        EC_POINT_free(pt);
        EC_KEY_free(ec);
        return ErrorCode::HSM_KEY_GENERATION_FAILED;
    }
    EC_KEY_set_public_key(ec, pt);
    EC_POINT_free(pt);

    BIGNUM* priv_bn = BN_bin2bn(it->second.priv.data(),
                                 static_cast<int>(it->second.priv.size()), nullptr);
    if (!priv_bn) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }
    EC_KEY_set_private_key(ec, priv_bn);
    BN_free(priv_bn);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);

    unsigned int sig_len = ECDSA_size(ec);
    signature.resize(sig_len);
    if (ECDSA_sign(0, digest, SHA256_DIGEST_LENGTH, signature.data(), &sig_len, ec) != 1) {
        EC_KEY_free(ec);
        return ErrorCode::HSM_SIGN_FAILED;
    }
    signature.resize(sig_len);
    EC_KEY_free(ec);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::verify(const std::string& key_id,
                              const std::vector<uint8_t>& data,
                              const std::vector<uint8_t>& signature,
                              bool& valid) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::HSM_VERIFICATION_FAILED;

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (!pt) { EC_KEY_free(ec); return ErrorCode::HSM_VERIFICATION_FAILED; }
    if (EC_POINT_oct2point(group, pt, it->second.pub.data(), it->second.pub.size(), nullptr) != 1) {
        EC_POINT_free(pt);
        EC_KEY_free(ec);
        return ErrorCode::HSM_KEY_GENERATION_FAILED;
    }
    EC_KEY_set_public_key(ec, pt);
    EC_POINT_free(pt);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);

    int result = ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH,
                              signature.data(), static_cast<int>(signature.size()), ec);
    EC_KEY_free(ec);

    valid = (result == 1);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::export_public_key(const std::string& key_id,
                                         std::vector<uint8_t>& public_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    public_key = it->second.pub;
    return ErrorCode::SUCCESS;
}

bool SoftFileHsm::key_exists(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_valid_key_id(key_id)) return false;
    if (keys_.find(key_id) != keys_.end()) return true;

    try {
        return store_.has("key_metadata_" + key_id);
    } catch (const hwyz::store::StoreException& e) {
        return false;
    }
}

ErrorCode SoftFileHsm::delete_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it != keys_.end()) {
        secure_zero(it->second.priv);
        keys_.erase(it);
    }

    try {
        store_.remove("encrypted_private_key_" + key_id);
        store_.remove("key_metadata_" + key_id);
    } catch (const hwyz::store::StoreException& e) {
        std::cerr << "Failed to delete key from store: " << e.what() << std::endl;
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    return ErrorCode::SUCCESS;
}

std::string SoftFileHsm::get_status() const {
    return "SoftFile HSM (store, algo=" + encryption_algo_ + ")";
}

ErrorCode SoftFileHsm::export_private_key(const std::string& key_id,
                                          std::vector<uint8_t>& private_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    private_key = it->second.priv;
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::save_key_to_store(const std::string& key_id, const KeyData& key_data) {
    try {
        // 1. Encrypt private key first
        std::vector<uint8_t> encrypted_key;
        auto rc = encrypt_private_key(key_data.priv, encrypted_key);
        if (rc != ErrorCode::SUCCESS) {
            return rc;
        }

        // 2. Save encrypted key first (leaf data)
        store_.save("encrypted_private_key_" + key_id, bytes_to_hex(encrypted_key));

        // 3. Save metadata last (commit marker)
        nlohmann::json metadata;
        metadata["key_id"] = key_id;
        metadata["algorithm"] = key_data.algorithm;
        metadata["created_at"] = std::chrono::duration_cast<std::chrono::seconds>(
            key_data.created_at.time_since_epoch()).count();
        metadata["public_key"] = bytes_to_hex(key_data.pub);
        store_.save("key_metadata_" + key_id, metadata.dump());

        return ErrorCode::SUCCESS;
    } catch (const hwyz::store::StoreException& e) {
        std::cerr << "Failed to save key to store: " << e.what() << std::endl;
        return ErrorCode::STORAGE_WRITE_FAILED;
    }
}

ErrorCode SoftFileHsm::load_key_from_store(const std::string& key_id, KeyData& key_data) {
    try {
        if (!store_.has("key_metadata_" + key_id)) {
            return ErrorCode::KEY_NOT_FOUND;
        }

        std::string json_str = store_.load<std::string>("key_metadata_" + key_id);
        auto metadata = nlohmann::json::parse(json_str);

        key_data.algorithm = metadata.at("algorithm").get<std::string>();

        auto pub_hex = metadata.at("public_key").get<std::string>();
        key_data.pub = hex_to_bytes(pub_hex);

        auto enc_hex = store_.load<std::string>("encrypted_private_key_" + key_id);
        std::vector<uint8_t> encrypted_key = hex_to_bytes(enc_hex);

        auto rc = decrypt_private_key(encrypted_key, key_data.priv);
        if (rc != ErrorCode::SUCCESS) return rc;

        auto ts = metadata.at("created_at").get<int64_t>();
        key_data.created_at = std::chrono::system_clock::time_point(std::chrono::seconds(ts));

        return ErrorCode::SUCCESS;
    } catch (const hwyz::store::StoreException& e) {
        if (e.getError().code == hwyz::store::StoreError::kKeyNotFound) {
            return ErrorCode::KEY_NOT_FOUND;
        }
        std::cerr << "Failed to load key from store: " << e.what() << std::endl;
        return ErrorCode::STORAGE_READ_FAILED;
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse key from store: " << e.what() << std::endl;
        return ErrorCode::STORAGE_CORRUPTION;
    }
}

ErrorCode SoftFileHsm::encrypt_private_key(const std::vector<uint8_t>& plain_key,
                                           std::vector<uint8_t>& encrypted_key) {
    if (encryption_key_.size() != ENCRYPTION_KEY_SIZE) return ErrorCode::INTERNAL_ERROR;

    std::vector<uint8_t> iv(AES_GCM_IV_SIZE);
    if (RAND_bytes(iv.data(), AES_GCM_IV_SIZE) != 1) return ErrorCode::INTERNAL_ERROR;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ErrorCode::INTERNAL_ERROR;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }

    std::vector<uint8_t> ciphertext(plain_key.size() + AES_GCM_TAG_SIZE);
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                          plain_key.data(), static_cast<int>(plain_key.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    int total = out_len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    total += out_len;

    std::vector<uint8_t> tag(AES_GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    EVP_CIPHER_CTX_free(ctx);

    encrypted_key.clear();
    encrypted_key.insert(encrypted_key.end(), iv.begin(), iv.end());
    encrypted_key.insert(encrypted_key.end(), ciphertext.begin(), ciphertext.begin() + total);
    encrypted_key.insert(encrypted_key.end(), tag.begin(), tag.end());

    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::decrypt_private_key(const std::vector<uint8_t>& encrypted_key,
                                           std::vector<uint8_t>& plain_key) {
    if (encryption_key_.size() != ENCRYPTION_KEY_SIZE) return ErrorCode::INTERNAL_ERROR;

    if (encrypted_key.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
        return ErrorCode::STORAGE_CORRUPTION;
    }

    const uint8_t* iv = encrypted_key.data();
    const uint8_t* tag = encrypted_key.data() + encrypted_key.size() - AES_GCM_TAG_SIZE;
    const uint8_t* ciphertext = encrypted_key.data() + AES_GCM_IV_SIZE;
    int ciphertext_len = static_cast<int>(encrypted_key.size() - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ErrorCode::INTERNAL_ERROR;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }

    plain_key.resize(ciphertext_len + AES_GCM_TAG_SIZE);
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, plain_key.data(), &out_len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    int total = out_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                            const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }

    if (EVP_DecryptFinal_ex(ctx, plain_key.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::STORAGE_CORRUPTION;
    }
    total += out_len;
    plain_key.resize(total);

    EVP_CIPHER_CTX_free(ctx);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::generate_encryption_key() {
    encryption_key_.resize(ENCRYPTION_KEY_SIZE);
    if (RAND_bytes(encryption_key_.data(), ENCRYPTION_KEY_SIZE) != 1) {
        return ErrorCode::INTERNAL_ERROR;
    }

    fs::path p(encryption_key_path_);
    if (p.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(p.parent_path(), ec);
    }

    std::ofstream ofs(encryption_key_path_, std::ios::binary);
    if (!ofs.is_open()) return ErrorCode::STORAGE_WRITE_FAILED;
    ofs.write(reinterpret_cast<const char*>(encryption_key_.data()), ENCRYPTION_KEY_SIZE);
    ofs.close();

    fs::permissions(encryption_key_path_,
                    fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace);

    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::load_encryption_key() {
    std::ifstream ifs(encryption_key_path_, std::ios::binary);
    if (!ifs.is_open()) return ErrorCode::STORAGE_READ_FAILED;

    encryption_key_.resize(ENCRYPTION_KEY_SIZE);
    ifs.read(reinterpret_cast<char*>(encryption_key_.data()), ENCRYPTION_KEY_SIZE);
    if (ifs.gcount() != ENCRYPTION_KEY_SIZE) {
        encryption_key_.clear();
        return ErrorCode::STORAGE_CORRUPTION;
    }

    return ErrorCode::SUCCESS;
}

void SoftFileHsm::secure_zero(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

bool SoftFileHsm::is_valid_key_id(const std::string& key_id) const {
    return key_id.find("..") == std::string::npos &&
           key_id.find('/') == std::string::npos &&
           key_id.find('\\') == std::string::npos;
}

std::string SoftFileHsm::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::string hex;
    hex.reserve(bytes.size() * 2);
    char buf[3];
    for (auto b : bytes) {
        snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return hex;
}

std::vector<uint8_t> SoftFileHsm::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

} // namespace sec
} // namespace tbox
