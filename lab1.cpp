#include <iostream>
#include <vector>
#include <cstdint>
#include <bitset>
#include <string>
#include <future>
#include <memory>
#include <any>
#include <stdexcept>

using Bytes = std::vector<std::uint8_t>;
using RoundKeys = std::vector<Bytes>;

class IKeyExpansion {
public:
    virtual ~IKeyExpansion() = default;

    virtual RoundKeys expand_key(const Bytes& key) const = 0;

    virtual std::future<RoundKeys> expand_key_async(const Bytes& key) const {
        return std::async(std::launch::async,
                          [this, key]{ return expand_key(key); });
    }
};

class IBlockCipher {
public:
    virtual ~IBlockCipher() = default;

    virtual std::size_t block_size() const = 0;

    virtual Bytes encrypt_block(const Bytes& block,
                                const Bytes& round_key) const = 0;
    virtual Bytes decrypt_block(const Bytes& block,
                                const Bytes& round_key) const = 0;
};

class ISymmetricCipher {
public:
    virtual ~ISymmetricCipher() = default;

    virtual void set_key(const Bytes& key) = 0;

    virtual Bytes encrypt(const Bytes& block) const = 0;
    virtual Bytes decrypt(const Bytes& block) const = 0;

    virtual std::future<Bytes> encrypt_async(const Bytes& block) const {
        return std::async(std::launch::async,
                          [this, block]{ return encrypt(block); });
    }
    virtual std::future<Bytes> decrypt_async(const Bytes& block) const {
        return std::async(std::launch::async,
                          [this, block]{ return decrypt(block); });
    }

    virtual std::size_t block_size() const = 0;
};

enum class CipherMode {
    ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta
};

enum class PaddingMode {
    Zeros,
    ANSI_X923,
    PKCS7,
    ISO_10126
};

class SymmetricCipherContext : public ISymmetricCipher {
public:
    SymmetricCipherContext(
        const Bytes& key,
        CipherMode mode,
        PaddingMode padding,
        const Bytes& iv = {},
        const std::vector<std::any>& extra = {}
    );

    void set_key(const Bytes& key) override;

    Bytes encrypt(const Bytes& block) const override;
    Bytes decrypt(const Bytes& block) const override;

    void encrypt(const Bytes& data, Bytes& out) const;
    void decrypt(const Bytes& data, Bytes& out) const;

    std::future<void> encrypt_async(const Bytes& data, Bytes& out) const;
    std::future<void> decrypt_async(const Bytes& data, Bytes& out) const;

    void encrypt_file(const std::string& in_path,
                      const std::string& out_path) const;
    void decrypt_file(const std::string& in_path,
                      const std::string& out_path) const;

    std::future<void> encrypt_file_async(const std::string& in_path,
                                         const std::string& out_path) const;
    std::future<void> decrypt_file_async(const std::string& in_path,
                                         const std::string& out_path) const;

    std::size_t block_size() const override;

private:
    Bytes m_key;
    RoundKeys m_round_keys;
    CipherMode m_mode;
    PaddingMode m_padding;
    Bytes m_iv;
    std::vector<std::any> m_extra;

    std::shared_ptr<IKeyExpansion> m_key_expander;
    std::shared_ptr<IBlockCipher> m_block_cipher;

    Bytes pad(const Bytes& data) const;
    Bytes unpad(const Bytes& data) const;

    Bytes apply_mode_encrypt(const Bytes& data) const;
    Bytes apply_mode_decrypt(const Bytes& data) const;

    Bytes parallel_blocks(const Bytes& data, bool encrypt) const;
};

std::uint8_t value = 0b10110010;

std::vector<int> p_block = {2, 0, 7, 4, 6, 1, 5, 3};

void permute_bits (
    std::uint8_t *value,
    const std::vector<int> &p_block,
    bool least_significant_first,
    bool zero_is_first
) {
    std::uint8_t result = 0;

    for (int i = 0; i < p_block.size(); ++i) {
        int source = p_block[i];
        int destination = i;

        if (!zero_is_first) {
            source -= 1;
        }

        if (!least_significant_first) {
            source = 7 - source;
        }

        bool bit = (*value >> source) & 1;

        if (bit) {
            result |= (1 << destination);
        }
    }

    *value = result;
}

int main() {
    permute_bits(&value, p_block, true, true);

    std::cout << std::bitset<8>(value) << '\n';

    return 0;
}