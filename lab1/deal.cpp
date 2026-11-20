#include "crypto.hpp"

namespace {
class DEALRoundTransform : public IRoundTransform {
public:
    Bytes apply(const Bytes& halfBlock, const Bytes& roundKey) const override {
        if (roundKey.size() != 8) {
            throw std::invalid_argument("DEAL round key must contain 8 bytes");
        }
        const std::string cacheKey(reinterpret_cast<const char*>(roundKey.data()), roundKey.size());
        std::shared_ptr<const DESCipher> des;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto found = cache_.find(cacheKey);
            if (found != cache_.end()) {
                des = found->second;
            } else {
                auto prepared = std::make_shared<DESCipher>();
                prepared->setKey(roundKey);
                des = prepared;
                cache_.emplace(cacheKey, std::move(prepared));
            }
        }
        return des->encryptBlock(halfBlock);
    }

private:
    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, std::shared_ptr<const DESCipher>> cache_;
};

}

std::vector<Bytes> DEALKeyExpansion::expand(const Bytes& key) const {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::invalid_argument("DEAL key must contain 16, 24, or 32 bytes");
    }
    const std::size_t rounds = key.size() == 32 ? 8 : 6;
    DESCipher des;
    des.setKey(Bytes{0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef});
    std::vector<Bytes> masterKeys;
    for (std::size_t i = 0; i < key.size(); i += 8) {
        masterKeys.emplace_back(key.begin() + static_cast<std::ptrdiff_t>(i),
                                key.begin() + static_cast<std::ptrdiff_t>(i + 8));
    }
    std::vector<Bytes> result;
    Bytes state(8, 0);
    for (std::size_t i = 0; i < rounds; ++i) {
        std::size_t wordIndex = 0;
        bool hasConstant = false;
        std::size_t constantIndex = 0;
        if (masterKeys.size() == 2) {
            wordIndex = i % 2;
            hasConstant = i >= 2;
            constantIndex = i - 2;
        } else if (masterKeys.size() == 3) {
            wordIndex = i < 3 ? i : i - 3;
            hasConstant = i >= 3;
            constantIndex = i - 3;
        } else {
            const std::array<std::size_t, 8> indices = {0,1,2,3,1,1,2,3};
            wordIndex = indices[i];
            hasConstant = i >= 4;
            constantIndex = i - 4;
        }
        Bytes input = xorBytes(masterKeys[wordIndex], state);
        if (hasConstant) {
            input[constantIndex / 8] ^= static_cast<std::uint8_t>(0x80U >> (constantIndex % 8));
        }
        state = des.encryptBlock(input);
        result.push_back(state);
    }
    return result;
}
DEALCipher::DEALCipher()
    : network_(std::make_shared<DEALKeyExpansion>(),
               std::make_shared<DEALRoundTransform>(), 16) {}

void DEALCipher::setKey(const Bytes& key) {
    network_.setKey(key);
}

Bytes DEALCipher::encryptBlock(const Bytes& block) const {
    if (block.size() != 16) {
        throw std::invalid_argument("DEAL block must contain 16 bytes");
    }
    Bytes reversed(block.begin() + 8, block.end());
    reversed.insert(reversed.end(), block.begin(), block.begin() + 8);
    return network_.encryptBlock(reversed);
}

Bytes DEALCipher::decryptBlock(const Bytes& block) const {
    if (block.size() != 16) {
        throw std::invalid_argument("DEAL block must contain 16 bytes");
    }
    Bytes reversed = network_.decryptBlock(block);
    std::rotate(reversed.begin(), reversed.begin() + 8, reversed.end());
    return reversed;
}

std::size_t DEALCipher::blockSize() const {
    return 16;
}
