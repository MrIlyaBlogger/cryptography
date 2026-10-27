#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <future>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// The assignment uses byte arrays as the common representation of values.
using Bytes = std::vector<std::uint8_t>;

enum class BitOrder { LeastSignificantFirst, MostSignificantFirst };
enum class FirstBitNumber { Zero, One };

namespace {

bool getBit(const Bytes& bytes, std::size_t sequenceIndex, BitOrder order) {
    const std::size_t byteIndex = sequenceIndex / 8;
    const std::size_t offsetInByte = sequenceIndex % 8;
    const std::size_t shift = order == BitOrder::LeastSignificantFirst
                                  ? offsetInByte : 7 - offsetInByte;
    return ((bytes[byteIndex] >> shift) & 1U) != 0;
}

void setBit(Bytes& bytes, std::size_t sequenceIndex, BitOrder order) {
    const std::size_t byteIndex = sequenceIndex / 8;
    const std::size_t offsetInByte = sequenceIndex % 8;
    const std::size_t shift = order == BitOrder::LeastSignificantFirst
                                  ? offsetInByte : 7 - offsetInByte;
    bytes[byteIndex] |= static_cast<std::uint8_t>(1U << shift);
}

Bytes xorBytes(const Bytes& left, const Bytes& right) {
    if (left.size() != right.size()) throw std::invalid_argument("XOR operands must have equal length");
    Bytes result(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) result[i] = left[i] ^ right[i];
    return result;
}

Bytes readFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot open input file: " + path);
    return Bytes(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void writeFile(const std::string& path, const Bytes& data) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Cannot open output file: " + path);
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!output) throw std::runtime_error("Failed to write output file: " + path);
}

} // namespace

// P-block entries name input bits; output position i receives pBlock[i].
// Bit positions are ordered byte by byte, with order defining the direction
// inside each byte. Unused high/low bits of a partial result byte remain zero.
Bytes permuteBits(const Bytes& value, const std::vector<std::size_t>& pBlock,
                  BitOrder order, FirstBitNumber firstBitNumber) {
    const std::size_t firstBit = firstBitNumber == FirstBitNumber::Zero ? 0 : 1;
    if (value.size() > static_cast<std::size_t>(-1) / 8 ||
        pBlock.size() > static_cast<std::size_t>(-1) - 7)
        throw std::length_error("Bit array is too large");
    const std::size_t inputBitCount = value.size() * 8;
    Bytes result((pBlock.size() + 7) / 8, 0);
    for (std::size_t outputIndex = 0; outputIndex < pBlock.size(); ++outputIndex) {
        const std::size_t numberedInputBit = pBlock[outputIndex];
        if (numberedInputBit < firstBit || numberedInputBit - firstBit >= inputBitCount)
            throw std::out_of_range("P-block contains a bit number outside the input value");
        if (getBit(value, numberedInputBit - firstBit, order)) setBit(result, outputIndex, order);
    }
    return result;
}

// Interfaces corresponding to задания 2.1-2.3.
class IKeyExpansion {
public:
    virtual ~IKeyExpansion() = default;
    virtual std::vector<Bytes> expand(const Bytes& key) const = 0;
};

class IRoundTransform {
public:
    virtual ~IRoundTransform() = default;
    virtual Bytes apply(const Bytes& halfBlock, const Bytes& roundKey) const = 0;
};

class ISymmetricCipher {
public:
    virtual ~ISymmetricCipher() = default;
    virtual void setKey(const Bytes& key) = 0;
    virtual Bytes encryptBlock(const Bytes& block) const = 0;
    virtual Bytes decryptBlock(const Bytes& block) const = 0;
    virtual std::size_t blockSize() const = 0;
};

enum class CipherMode { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta };
enum class PaddingMode { Zeros, ANSI_X923, PKCS7, ISO10126 };

// Generic Feistel network. The supplied round function operates on one half.
class FeistelCipher : public ISymmetricCipher {
public:
    FeistelCipher(std::shared_ptr<const IKeyExpansion> keyExpansion,
                  std::shared_ptr<const IRoundTransform> roundTransform,
                  std::size_t blockBytes)
        : keyExpansion_(std::move(keyExpansion)), roundTransform_(std::move(roundTransform)),
          blockBytes_(blockBytes) {
        if (!keyExpansion_ || !roundTransform_ || blockBytes_ == 0 || blockBytes_ % 2 != 0)
            throw std::invalid_argument("Feistel cipher requires valid components and an even block size");
    }

    void setKey(const Bytes& key) override {
        roundKeys_ = keyExpansion_->expand(key);
        if (roundKeys_.empty()) throw std::invalid_argument("Key expansion returned no round keys");
    }

    Bytes encryptBlock(const Bytes& block) const override { return process(block, false); }
    Bytes decryptBlock(const Bytes& block) const override { return process(block, true); }
    std::size_t blockSize() const override { return blockBytes_; }

private:
    Bytes process(const Bytes& block, bool reverse) const {
        if (roundKeys_.empty()) throw std::logic_error("Set the cipher key before using it");
        if (block.size() != blockBytes_) throw std::invalid_argument("Invalid block length");
        const std::size_t halfSize = blockBytes_ / 2;
        Bytes left(block.begin(), block.begin() + static_cast<std::ptrdiff_t>(halfSize));
        Bytes right(block.begin() + static_cast<std::ptrdiff_t>(halfSize), block.end());
        for (std::size_t round = 0; round < roundKeys_.size(); ++round) {
            const std::size_t keyIndex = reverse ? roundKeys_.size() - 1 - round : round;
            Bytes next = xorBytes(left, roundTransform_->apply(right, roundKeys_[keyIndex]));
            left = std::move(right);
            right = std::move(next);
        }
        left.swap(right); // Feistel final half swap.
        left.insert(left.end(), right.begin(), right.end());
        return left;
    }

    std::shared_ptr<const IKeyExpansion> keyExpansion_;
    std::shared_ptr<const IRoundTransform> roundTransform_;
    std::size_t blockBytes_;
    std::vector<Bytes> roundKeys_;
};

namespace {

Bytes permuteDes(const Bytes& input, const std::vector<std::size_t>& table) {
    std::vector<std::size_t> zeroBased;
    zeroBased.reserve(table.size());
    for (std::size_t bit : table) zeroBased.push_back(bit - 1);
    return permuteBits(input, zeroBased, BitOrder::MostSignificantFirst, FirstBitNumber::Zero);
}

constexpr std::array<std::size_t, 64> IP = {
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
constexpr std::array<std::size_t, 64> FP = {
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
constexpr std::array<std::size_t, 56> PC1 = {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
    60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
    29,21,13,5,28,20,12,4};
constexpr std::array<std::size_t, 48> PC2 = {
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
constexpr std::array<std::size_t, 48> E = {
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
constexpr std::array<std::size_t, 32> P = {
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
constexpr std::array<unsigned, 16> SHIFTS = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
constexpr unsigned SBOX[8][4][16] = {
 {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
 {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
 {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
 {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
 {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
 {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
 {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
 {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

class DESKeyExpansion : public IKeyExpansion {
public:
    std::vector<Bytes> expand(const Bytes& key) const override {
        if (key.size() != 8) throw std::invalid_argument("DES key must contain 8 bytes");
        Bytes selected = permuteDes(key, std::vector<std::size_t>(PC1.begin(), PC1.end()));
        Bytes c(selected.begin(), selected.begin() + 4), d(4, 0);
        for (std::size_t i = 0; i < 28; ++i) if (getBit(selected, i + 28, BitOrder::MostSignificantFirst)) setBit(d, i, BitOrder::MostSignificantFirst);
        std::vector<Bytes> keys;
        for (unsigned shift : SHIFTS) {
            // Use an explicit rotation to avoid depending on host integer width.
            auto rotateHalf = [shift](Bytes& half) {
                std::array<bool, 28> bits{}; Bytes result(4, 0);
                for (std::size_t i = 0; i < 28; ++i) bits[i] = getBit(half, i, BitOrder::MostSignificantFirst);
                for (std::size_t i = 0; i < 28; ++i) if (bits[(i + shift) % 28]) setBit(result, i, BitOrder::MostSignificantFirst);
                half = std::move(result);
            };
            rotateHalf(c); rotateHalf(d);
            Bytes joined(7, 0);
            for (std::size_t bit = 0; bit < 28; ++bit) {
                if (getBit(c, bit, BitOrder::MostSignificantFirst))
                    setBit(joined, bit, BitOrder::MostSignificantFirst);
                if (getBit(d, bit, BitOrder::MostSignificantFirst))
                    setBit(joined, bit + 28, BitOrder::MostSignificantFirst);
            }
            keys.push_back(permuteDes(joined, std::vector<std::size_t>(PC2.begin(), PC2.end())));
        }
        return keys;
    }
};

class DESRoundTransform : public IRoundTransform {
public:
    Bytes apply(const Bytes& halfBlock, const Bytes& roundKey) const override {
        if (halfBlock.size() != 4 || roundKey.size() != 6) throw std::invalid_argument("Invalid DES round input");
        Bytes expanded = permuteDes(halfBlock, std::vector<std::size_t>(E.begin(), E.end()));
        expanded = xorBytes(expanded, roundKey);
        Bytes substituted(4, 0);
        for (std::size_t box = 0; box < 8; ++box) {
            const std::size_t offset = box * 6;
            const unsigned row = (getBit(expanded, offset, BitOrder::MostSignificantFirst) ? 2U : 0U) |
                                 (getBit(expanded, offset + 5, BitOrder::MostSignificantFirst) ? 1U : 0U);
            unsigned column = 0;
            for (std::size_t bit = 1; bit <= 4; ++bit) column = (column << 1U) | (getBit(expanded, offset + bit, BitOrder::MostSignificantFirst) ? 1U : 0U);
            const unsigned value = SBOX[box][row][column];
            for (unsigned bit = 0; bit < 4; ++bit) if ((value >> (3U - bit)) & 1U) setBit(substituted, box * 4 + bit, BitOrder::MostSignificantFirst);
        }
        return permuteDes(substituted, std::vector<std::size_t>(P.begin(), P.end()));
    }
};

} // namespace

class DESCipher : public ISymmetricCipher {
public:
    DESCipher() : network_(std::make_shared<DESKeyExpansion>(), std::make_shared<DESRoundTransform>(), 8) {}
    void setKey(const Bytes& key) override { network_.setKey(key); }
    std::size_t blockSize() const override { return 8; }
    Bytes encryptBlock(const Bytes& block) const override {
        return permuteDes(network_.encryptBlock(permuteDes(block, std::vector<std::size_t>(IP.begin(), IP.end()))), std::vector<std::size_t>(FP.begin(), FP.end()));
    }
    Bytes decryptBlock(const Bytes& block) const override {
        return permuteDes(network_.decryptBlock(permuteDes(block, std::vector<std::size_t>(IP.begin(), IP.end()))), std::vector<std::size_t>(FP.begin(), FP.end()));
    }
private:
    FeistelCipher network_;
};

// DEAL uses DES as its round function over 64-bit Feistel halves. The key
// schedule derives an 8-byte DES key for every round from 128/192/256-bit keys.
class DEALKeyExpansion : public IKeyExpansion {
public:
    std::vector<Bytes> expand(const Bytes& key) const override {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32)
            throw std::invalid_argument("DEAL key must contain 16, 24, or 32 bytes");
        const std::size_t rounds = key.size() == 32 ? 8 : 6;
        DESCipher des;
        des.setKey(Bytes{0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef});
        std::vector<Bytes> masterKeys;
        for (std::size_t i = 0; i < key.size(); i += 8)
            masterKeys.emplace_back(key.begin() + static_cast<std::ptrdiff_t>(i),
                                     key.begin() + static_cast<std::ptrdiff_t>(i + 8));
        std::vector<Bytes> result;
        Bytes state(8, 0);
        // DEAL-128/192/256 extend the input key words with the published
        // recurrence; round constants are the first, second, fourth, and
        // eighth MSB-first bit of a 64-bit word.
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
            if (hasConstant) input[constantIndex / 8] ^= static_cast<std::uint8_t>(0x80U >> (constantIndex % 8));
            state = des.encryptBlock(input);
            result.push_back(state);
        }
        return result;
    }
};

class DEALRoundTransform : public IRoundTransform {
public:
    Bytes apply(const Bytes& halfBlock, const Bytes& roundKey) const override {
        DESCipher des; des.setKey(roundKey); return des.encryptBlock(halfBlock);
    }
};

class DEALCipher : public ISymmetricCipher {
public:
    DEALCipher() : network_(std::make_shared<DEALKeyExpansion>(), std::make_shared<DEALRoundTransform>(), 16) {}
    void setKey(const Bytes& key) override { network_.setKey(key); }
    Bytes encryptBlock(const Bytes& block) const override {
        if (block.size() != 16) throw std::invalid_argument("DEAL block must contain 16 bytes");
        Bytes reversed(block.begin() + 8, block.end());
        reversed.insert(reversed.end(), block.begin(), block.begin() + 8);
        return network_.encryptBlock(reversed);
    }
    Bytes decryptBlock(const Bytes& block) const override {
        if (block.size() != 16) throw std::invalid_argument("DEAL block must contain 16 bytes");
        Bytes reversed = network_.decryptBlock(block);
        std::rotate(reversed.begin(), reversed.begin() + 8, reversed.end());
        return reversed;
    }
    std::size_t blockSize() const override { return 16; }
private:
    FeistelCipher network_;
};

// Context for data buffers and files. File operations and buffer operations
// have asynchronous variants returning futures as requested in the assignment.
class CipherContext {
public:
    CipherContext(std::shared_ptr<ISymmetricCipher> cipher, const Bytes& key,
                  CipherMode mode, PaddingMode padding, Bytes iv = {},
                  std::vector<Bytes> extraParameters = {})
        : cipher_(std::move(cipher)), mode_(mode), padding_(padding), iv_(std::move(iv)),
          extra_(std::move(extraParameters)) {
        if (!cipher_) throw std::invalid_argument("Cipher must not be null");
        cipher_->setKey(key);
        const std::size_t n = cipher_->blockSize();
        if (mode_ == CipherMode::RandomDelta && iv_.empty())
            throw std::invalid_argument("RandomDelta requires an explicit initial counter in iv");
        if (iv_.empty()) iv_.assign(n, 0);
        if (iv_.size() != n) throw std::invalid_argument("IV length must equal the cipher block size");
        if (mode_ == CipherMode::RandomDelta && extra_.empty())
            throw std::invalid_argument("RandomDelta requires an explicit increment in extraParameters");
        delta_ = extra_.empty() ? Bytes(n, 0) : extra_.front();
        if (delta_.size() != n) throw std::invalid_argument("RandomDelta increment must equal the block size");
        if (extra_.empty()) delta_.back() = 1;
        if (std::all_of(delta_.begin(), delta_.end(), [](std::uint8_t b) { return b == 0; }))
            throw std::invalid_argument("RandomDelta increment must be nonzero");
    }

    Bytes encrypt(const Bytes& input) const { return transform(input, false); }
    Bytes decrypt(const Bytes& input) const { return transform(input, true); }
    std::future<Bytes> encryptAsync(Bytes input) const {
        return std::async(std::launch::async, [this, input = std::move(input)] { return encrypt(input); });
    }
    std::future<Bytes> decryptAsync(Bytes input) const {
        return std::async(std::launch::async, [this, input = std::move(input)] { return decrypt(input); });
    }
    std::future<void> encryptFileAsync(std::string inputPath, std::string outputPath) const {
        return std::async(std::launch::async, [this, inputPath = std::move(inputPath), outputPath = std::move(outputPath)] {
            writeFile(outputPath, encrypt(readFile(inputPath)));
        });
    }
    std::future<void> decryptFileAsync(std::string inputPath, std::string outputPath) const {
        return std::async(std::launch::async, [this, inputPath = std::move(inputPath), outputPath = std::move(outputPath)] {
            writeFile(outputPath, decrypt(readFile(inputPath)));
        });
    }

private:
    Bytes addPadding(Bytes data) const {
        const std::size_t n = cipher_->blockSize();
        const std::size_t remainder = data.size() % n;
        if (padding_ == PaddingMode::Zeros) {
            if (remainder) data.resize(data.size() + n - remainder, 0);
            return data;
        }
        const std::size_t count = n - remainder;
        if (padding_ == PaddingMode::ANSI_X923) {
            data.resize(data.size() + count, 0); data.back() = static_cast<std::uint8_t>(count);
        } else if (padding_ == PaddingMode::PKCS7) {
            data.resize(data.size() + count, static_cast<std::uint8_t>(count));
        } else {
            const std::size_t old = data.size(); data.resize(old + count);
            if (count > 1) {
                std::random_device random;
                for (std::size_t i = old; i + 1 < data.size(); ++i) data[i] = static_cast<std::uint8_t>(random());
            }
            data.back() = static_cast<std::uint8_t>(count);
        }
        return data;
    }

    Bytes removePadding(Bytes data) const {
        if (data.empty()) return data;
        if (padding_ == PaddingMode::Zeros) {
            while (!data.empty() && data.back() == 0) data.pop_back();
            return data;
        }
        const std::size_t count = data.back();
        if (count == 0 || count > cipher_->blockSize() || count > data.size())
            throw std::runtime_error("Invalid padding");
        if (padding_ == PaddingMode::PKCS7) {
            for (std::size_t i = data.size() - count; i < data.size(); ++i)
                if (data[i] != count) throw std::runtime_error("Invalid PKCS7 padding");
        } else if (padding_ == PaddingMode::ANSI_X923) {
            for (std::size_t i = data.size() - count; i + 1 < data.size(); ++i)
                if (data[i] != 0) throw std::runtime_error("Invalid ANSI X.923 padding");
        }
        data.resize(data.size() - count);
        return data;
    }

    void addDelta(Bytes& counter) const {
        unsigned carry = 0;
        for (std::size_t i = counter.size(); i-- > 0;) {
            const unsigned sum = counter[i] + delta_[i] + carry;
            counter[i] = static_cast<std::uint8_t>(sum);
            carry = sum >> 8U;
        }
    }

    Bytes transform(const Bytes& input, bool decrypting) const {
        const std::size_t n = cipher_->blockSize();
        const bool streamMode = mode_ == CipherMode::CFB || mode_ == CipherMode::OFB ||
                                mode_ == CipherMode::CTR || mode_ == CipherMode::RandomDelta;
        Bytes data = streamMode ? input : (decrypting ? input : addPadding(input));
        if (!streamMode && data.size() % n != 0) throw std::invalid_argument("Ciphertext length is not block aligned");
        Bytes out; out.reserve(data.size()); Bytes feedback = iv_;
        for (std::size_t offset = 0; offset < data.size(); offset += n) {
            const std::size_t count = std::min(n, data.size() - offset);
            Bytes block(data.begin() + static_cast<std::ptrdiff_t>(offset), data.begin() + static_cast<std::ptrdiff_t>(offset + count));
            Bytes result;
            if (mode_ == CipherMode::ECB) {
                result = decrypting ? cipher_->decryptBlock(block) : cipher_->encryptBlock(block);
            } else if (mode_ == CipherMode::CBC) {
                if (decrypting) { result = xorBytes(cipher_->decryptBlock(block), feedback); feedback = block; }
                else { result = cipher_->encryptBlock(xorBytes(block, feedback)); feedback = result; }
            } else if (mode_ == CipherMode::PCBC) {
                if (decrypting) {
                    result = xorBytes(cipher_->decryptBlock(block), feedback);
                    feedback = xorBytes(block, result);
                } else {
                    result = cipher_->encryptBlock(xorBytes(block, feedback));
                    feedback = xorBytes(block, result);
                }
            } else {
                Bytes source = mode_ == CipherMode::CFB ? feedback : feedback;
                Bytes mask = cipher_->encryptBlock(source);
                if (mode_ == CipherMode::CFB) {
                    result = xorBytes(block, Bytes(mask.begin(), mask.begin() + static_cast<std::ptrdiff_t>(count)));
                    feedback = decrypting ? block : result;
                    if (count != n) { // Partial last segment is supported without feeding unused bytes.
                        feedback.assign(n, 0); std::copy(block.begin(), block.end(), feedback.begin());
                    }
                } else {
                    result.resize(count);
                    for (std::size_t i = 0; i < count; ++i) result[i] = block[i] ^ mask[i];
                    if (mode_ == CipherMode::OFB) feedback = std::move(mask);
                    else addDelta(feedback); // CTR and RandomDelta differ by their configured increment.
                }
            }
            out.insert(out.end(), result.begin(), result.end());
        }
        return decrypting && !streamMode ? removePadding(std::move(out)) : out;
    }

    std::shared_ptr<ISymmetricCipher> cipher_;
    CipherMode mode_;
    PaddingMode padding_;
    Bytes iv_;
    std::vector<Bytes> extra_;
    Bytes delta_;
};

namespace {

std::string toHex(const Bytes& bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result; result.reserve(bytes.size() * 2);
    for (std::uint8_t value : bytes) { result.push_back(digits[value >> 4]); result.push_back(digits[value & 0x0f]); }
    return result;
}

Bytes fromHex(const std::string& text) {
    if (text.size() % 2) throw std::invalid_argument("Hex string length must be even");
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
        throw std::invalid_argument("Invalid hexadecimal digit");
    };
    Bytes result; result.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) result.push_back(static_cast<std::uint8_t>((digit(text[i]) << 4) | digit(text[i + 1])));
    return result;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const Bytes key = fromHex("133457799BBCDFF1");
        auto des = std::make_shared<DESCipher>();
        if ((argc == 4 || argc == 5) &&
            (std::string(argv[1]) == "encrypt" || std::string(argv[1]) == "decrypt")) {
            const bool encrypting = std::string(argv[1]) == "encrypt";
            const std::string algorithm = argc == 5 ? argv[4] : "DES";
            std::shared_ptr<ISymmetricCipher> fileCipher;
            Bytes fileKey;
            Bytes fileIv;
            if (algorithm == "DES" || algorithm == "des") {
                fileCipher = std::make_shared<DESCipher>();
                fileKey = key;
                fileIv = fromHex("0102030405060708");
            } else if (algorithm == "DEAL" || algorithm == "deal") {
                fileCipher = std::make_shared<DEALCipher>();
                fileKey = fromHex("0123456789ABCDEFFEDCBA9876543210");
                fileIv = Bytes(16, 0x01);
            } else {
                throw std::invalid_argument("Algorithm must be DES or DEAL");
            }
            CipherContext fileContext(fileCipher, fileKey, CipherMode::CBC,
                                      PaddingMode::PKCS7, fileIv);
            if (encrypting) fileContext.encryptFileAsync(argv[2], argv[3]).get();
            else fileContext.decryptFileAsync(argv[2], argv[3]).get();
            std::cout << algorithm << "-CBC " << (encrypting ? "encrypted " : "decrypted ")
                      << argv[2] << " -> " << argv[3] << '\n';
            return 0;
        }
        const Bytes sample{'C','r','y','p','t','o','g','r','a','p','h','y'};
        const std::array<CipherMode, 7> modes = {CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
            CipherMode::CFB, CipherMode::OFB, CipherMode::CTR, CipherMode::RandomDelta};
        const std::array<const char*, 7> modeNames = {"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"};
        for (std::size_t i = 0; i < modes.size(); ++i) {
            std::vector<Bytes> extra;
            if (modes[i] == CipherMode::RandomDelta) extra.push_back(Bytes{0,0,0,0,0,0,0,3});
            CipherContext desContext(des, key, modes[i], PaddingMode::PKCS7,
                                     fromHex("0102030405060708"), extra);
            const Bytes ciphertext = desContext.encryptAsync(sample).get();
            const Bytes plaintext = desContext.decryptAsync(ciphertext).get();
            std::cout << "DES-" << modeNames[i] << ": " << toHex(ciphertext)
                      << " -> " << std::string(plaintext.begin(), plaintext.end()) << '\n';
        }

        const Bytes dealKey = fromHex("0123456789ABCDEFFEDCBA9876543210");
        auto deal = std::make_shared<DEALCipher>();
        for (std::size_t i = 0; i < modes.size(); ++i) {
            std::vector<Bytes> extra;
            if (modes[i] == CipherMode::RandomDelta) extra.push_back(Bytes(16, 0x01));
            CipherContext dealContext(deal, dealKey, modes[i], PaddingMode::PKCS7,
                                      Bytes(16, 0x01), extra);
            const Bytes ciphertext = dealContext.encryptAsync(sample).get();
            const Bytes plaintext = dealContext.decryptAsync(ciphertext).get();
            std::cout << "DEAL-" << modeNames[i] << ": " << toHex(ciphertext)
                      << " -> " << std::string(plaintext.begin(), plaintext.end()) << '\n';
        }
        std::cout << "File usage: " << argv[0] << " encrypt|decrypt input-file output-file [DES|DEAL]\n";
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
