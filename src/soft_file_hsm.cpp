#include "soft_file_hsm.h"
#include "constants.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <chrono>
#include <cstring>

namespace tbox {
namespace sec {

namespace fs = std::filesystem;
using json = nlohmann::json;

static constexpr int AES_GCM_IV_SIZE = 12;
static constexpr int AES_GCM_TAG_SIZE = 16;
static constexpr int ENCRYPTION_KEY_SIZE = 32;

SoftFileHsm::SoftFileHsm(const std::string& key_store_path,
                         const std::string& encryption_algo,
                         const std::string& encryption_key_path)
    : key_store_path_(key_store_path),
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

    std::error_code ec;
    if (!fs::exists(key_store_path_)) {
        if (!fs::create_directories(key_store_path_, ec)) {
            return ErrorCode::STORAGE_WRITE_FAILED;
        }
        fs::permissions(key_store_path_,
                        fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec,
                        fs::perm_options::replace);
    }

    if (fs::exists(encryption_key_path_)) {
        auto rc = load_encryption_key();
        if (rc != ErrorCode::SUCCESS) return rc;
    } else {
        auto rc = generate_encryption_key();
        if (rc != ErrorCode::SUCCESS) return rc;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::generate_key_pair(const std::string& key_id,
                                         const std::string& algorithm,
                                         KeyPair& key_pair) {
    std::lock_guard<std::mutex> lock(mutex_);

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

    auto rc = save_key_to_disk(key_id, kd);
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

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_disk(key_id, kd);
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

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_disk(key_id, kd);
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

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_disk(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    public_key = it->second.pub;
    return ErrorCode::SUCCESS;
}

bool SoftFileHsm::key_exists(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (keys_.find(key_id) != keys_.end()) return true;
    return fs::exists(get_key_file_path(key_id));
}

ErrorCode SoftFileHsm::delete_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = keys_.find(key_id);
    if (it != keys_.end()) {
        secure_zero(it->second.priv);
        keys_.erase(it);
    }

    std::error_code ec;
    fs::remove(get_key_file_path(key_id), ec);
    return ErrorCode::SUCCESS;
}

std::string SoftFileHsm::get_status() const {
    return "SoftFile HSM (key_store=" + key_store_path_ + ", algo=" + encryption_algo_ + ")";
}

ErrorCode SoftFileHsm::export_private_key(const std::string& key_id,
                                          std::vector<uint8_t>& private_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_disk(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    private_key = it->second.priv;
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::load_key_from_disk(const std::string& key_id, KeyData& key_data) {
    std::string path = get_key_file_path(key_id);
    if (!fs::exists(path)) return ErrorCode::KEY_NOT_FOUND;

    std::ifstream ifs(path);
    if (!ifs.is_open()) return ErrorCode::STORAGE_READ_FAILED;

    json j;
    try {
        ifs >> j;
    } catch (...) {
        return ErrorCode::STORAGE_READ_FAILED;
    }

    try {
        key_data.algorithm = j.at("algorithm").get<std::string>();
        auto pub_hex = j.at("public_key").get<std::string>();
        auto priv_enc_hex = j.at("private_key_encrypted").get<std::string>();

        key_data.pub.resize(pub_hex.size() / 2);
        for (size_t i = 0; i < key_data.pub.size(); ++i) {
            key_data.pub[i] = static_cast<uint8_t>(std::stoul(pub_hex.substr(i * 2, 2), nullptr, 16));
        }

        std::vector<uint8_t> priv_enc(priv_enc_hex.size() / 2);
        for (size_t i = 0; i < priv_enc.size(); ++i) {
            priv_enc[i] = static_cast<uint8_t>(std::stoul(priv_enc_hex.substr(i * 2, 2), nullptr, 16));
        }

        auto rc = decrypt_private_key(priv_enc, key_data.priv);
        if (rc != ErrorCode::SUCCESS) return rc;

        key_data.priv_encrypted_on_disk = true;
        auto ts = j.at("created_at").get<int64_t>();
        key_data.created_at = std::chrono::system_clock::time_point(std::chrono::seconds(ts));
    } catch (...) {
        return ErrorCode::STORAGE_CORRUPTION;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::save_key_to_disk(const std::string& key_id, const KeyData& key_data) {
    std::vector<uint8_t> enc_priv;
    auto rc = encrypt_private_key(key_data.priv, enc_priv);
    if (rc != ErrorCode::SUCCESS) return rc;

    auto to_hex = [](const std::vector<uint8_t>& v) {
        std::string h;
        h.reserve(v.size() * 2);
        char buf[3];
        for (auto b : v) {
            snprintf(buf, sizeof(buf), "%02x", b);
            h += buf;
        }
        return h;
    };

    json j;
    j["key_id"] = key_id;
    j["algorithm"] = key_data.algorithm;
    j["public_key"] = to_hex(key_data.pub);
    j["private_key_encrypted"] = to_hex(enc_priv);
    j["created_at"] = std::chrono::duration_cast<std::chrono::seconds>(
        key_data.created_at.time_since_epoch()).count();

    std::string path = get_key_file_path(key_id);
    std::ofstream ofs(path);
    if (!ofs.is_open()) return ErrorCode::STORAGE_WRITE_FAILED;

    ofs << j.dump(2);
    ofs.close();

    fs::permissions(path,
                    fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace);

    return ErrorCode::SUCCESS;
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

std::string SoftFileHsm::get_key_file_path(const std::string& key_id) {
    if (key_id.find("..") != std::string::npos ||
        key_id.find("/") != std::string::npos ||
        key_id.find("\\") != std::string::npos) {
        throw std::invalid_argument("Invalid key_id: contains path traversal characters");
    }

    std::string safe_id = key_id;
    for (auto& c : safe_id) {
        if (c == ':') c = '_';
    }
    return key_store_path_ + "/" + safe_id + ".json";
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

} // namespace sec
} // namespace tbox
