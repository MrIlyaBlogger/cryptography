#pragma once
#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using Bytes = std::vector<std::uint8_t>;

enum class BitOrder { LeastSignificantFirst, MostSignificantFirst };
enum class FirstBitNumber { Zero, One };

namespace lab1_detail {

inline bool getBit(const Bytes& bytes, std::size_t sequenceIndex, BitOrder order) {
    const std::size_t byteIndex = sequenceIndex / 8;
    const std::size_t offsetInByte = sequenceIndex % 8;
    const std::size_t shift = order == BitOrder::LeastSignificantFirst
                                  ? offsetInByte : 7 - offsetInByte;
    return ((bytes[byteIndex] >> shift) & 1U) != 0;
}

inline void setBit(Bytes& bytes, std::size_t sequenceIndex, BitOrder order) {
    const std::size_t byteIndex = sequenceIndex / 8;
    const std::size_t offsetInByte = sequenceIndex % 8;
    const std::size_t shift = order == BitOrder::LeastSignificantFirst
                                  ? offsetInByte : 7 - offsetInByte;
    bytes[byteIndex] |= static_cast<std::uint8_t>(1U << shift);
}

inline Bytes xorBytes(const Bytes& left, const Bytes& right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument("XOR operands must have equal length");
    }
    Bytes result(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) {
        result[i] = left[i] ^ right[i];
    }
    return result;
}

inline Bytes readFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Cannot open input file: " + path);
    }
    return Bytes(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

inline void writeFile(const std::string& path, const Bytes& data) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Cannot open output file: " + path);
    }
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!output) {
        throw std::runtime_error("Failed to write output file: " + path);
    }
}

}
using lab1_detail::getBit;
using lab1_detail::setBit;
using lab1_detail::xorBytes;
using lab1_detail::readFile;
using lab1_detail::writeFile;

inline Bytes permuteBits(const Bytes& value, const std::vector<std::size_t>& pBlock,
                  BitOrder order, FirstBitNumber firstBitNumber) {
    const std::size_t firstBit = firstBitNumber == FirstBitNumber::Zero ? 0 : 1;
    if (value.size() > static_cast<std::size_t>(-1) / 8 ||
        pBlock.size() > static_cast<std::size_t>(-1) - 7) {
        throw std::length_error("Bit array is too large");
    }
    const std::size_t inputBitCount = value.size() * 8;
    Bytes result((pBlock.size() + 7) / 8, 0);
    for (std::size_t outputIndex = 0; outputIndex < pBlock.size(); ++outputIndex) {
        const std::size_t numberedInputBit = pBlock[outputIndex];
        if (numberedInputBit < firstBit || numberedInputBit - firstBit >= inputBitCount) {
            throw std::out_of_range("P-block contains a bit number outside the input value");
        }
        if (getBit(value, numberedInputBit - firstBit, order)) {
            setBit(result, outputIndex, order);
        }
    }
    return result;
}

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

class FeistelCipher : public ISymmetricCipher {
public:
    FeistelCipher(std::shared_ptr<const IKeyExpansion> keyExpansion,
                  std::shared_ptr<const IRoundTransform> roundTransform,
                  std::size_t blockBytes)
        : keyExpansion_(std::move(keyExpansion)), roundTransform_(std::move(roundTransform)),
          blockBytes_(blockBytes) {
        if (!keyExpansion_ || !roundTransform_ || blockBytes_ == 0 || blockBytes_ % 2 != 0) {
            throw std::invalid_argument("Feistel cipher requires valid components and an even block size");
        }
    }

    void setKey(const Bytes& key) override {
        roundKeys_ = keyExpansion_->expand(key);
        if (roundKeys_.empty()) {
            throw std::invalid_argument("Key expansion returned no round keys");
        }
    }

    Bytes encryptBlock(const Bytes& block) const override { return process(block, false); }
    Bytes decryptBlock(const Bytes& block) const override { return process(block, true); }
    std::size_t blockSize() const override { return blockBytes_; }

private:
    Bytes process(const Bytes& block, bool reverse) const {
        if (roundKeys_.empty()) {
            throw std::logic_error("Set the cipher key before using it");
        }
        if (block.size() != blockBytes_) {
            throw std::invalid_argument("Invalid block length");
        }
        const std::size_t halfSize = blockBytes_ / 2;
        Bytes left(block.begin(), block.begin() + static_cast<std::ptrdiff_t>(halfSize));
        Bytes right(block.begin() + static_cast<std::ptrdiff_t>(halfSize), block.end());
        for (std::size_t round = 0; round < roundKeys_.size(); ++round) {
            const std::size_t keyIndex = reverse ? roundKeys_.size() - 1 - round : round;
            Bytes next = xorBytes(left, roundTransform_->apply(right, roundKeys_[keyIndex]));
            left = std::move(right);
            right = std::move(next);
        }
        left.swap(right);
        left.insert(left.end(), right.begin(), right.end());
        return left;
    }

    std::shared_ptr<const IKeyExpansion> keyExpansion_;
    std::shared_ptr<const IRoundTransform> roundTransform_;
    std::size_t blockBytes_;
    std::vector<Bytes> roundKeys_;
};

class DESCipher : public ISymmetricCipher {
public:
    DESCipher();
    void setKey(const Bytes& key) override;
    std::size_t blockSize() const override;
    Bytes encryptBlock(const Bytes& block) const override;
    Bytes decryptBlock(const Bytes& block) const override;

private:
    FeistelCipher network_;
};

class DEALKeyExpansion : public IKeyExpansion {
public:
    std::vector<Bytes> expand(const Bytes& key) const override;
};

class DEALCipher : public ISymmetricCipher {
public:
    DEALCipher();
    void setKey(const Bytes& key) override;
    Bytes encryptBlock(const Bytes& block) const override;
    Bytes decryptBlock(const Bytes& block) const override;
    std::size_t blockSize() const override;

private:
    FeistelCipher network_;
};
class CipherContext {
public:
    CipherContext(std::shared_ptr<ISymmetricCipher> cipher, const Bytes& key,
                  CipherMode mode, PaddingMode padding, Bytes iv = {},
                  std::vector<Bytes> extraParameters = {})
        : cipher_(std::move(cipher)), mode_(mode), padding_(padding), iv_(std::move(iv)),
          extra_(std::move(extraParameters)) {
        if (!cipher_) {
            throw std::invalid_argument("Cipher must not be null");
        }
        cipher_->setKey(key);
        const std::size_t n = cipher_->blockSize();
        if (mode_ == CipherMode::RandomDelta && iv_.empty()) {
            throw std::invalid_argument("RandomDelta requires an explicit initial counter in iv");
        }
        if (iv_.empty()) {
            iv_.assign(n, 0);
        }
        if (iv_.size() != n) {
            throw std::invalid_argument("IV length must equal the cipher block size");
        }
        if (mode_ == CipherMode::RandomDelta && extra_.empty()) {
            throw std::invalid_argument("RandomDelta requires an explicit increment in extraParameters");
        }
        delta_ = extra_.empty() ? Bytes(n, 0) : extra_.front();
        if (delta_.size() != n) {
            throw std::invalid_argument("RandomDelta increment must equal the block size");
        }
        if (extra_.empty()) {
            delta_.back() = 1;
        }
        if (std::all_of(delta_.begin(), delta_.end(), [](std::uint8_t b) { return b == 0; })) {
            throw std::invalid_argument("RandomDelta increment must be nonzero");
        }
    }

    Bytes encrypt(const Bytes& input) const { return transform(input, false); }
    Bytes decrypt(const Bytes& input) const { return transform(input, true); }
    std::future<Bytes> encryptAsync(Bytes input) const {
        return std::async(std::launch::async,
                          [this, input = std::move(input)] { return encrypt(input); });
    }
    std::future<Bytes> decryptAsync(Bytes input) const {
        return std::async(std::launch::async,
                          [this, input = std::move(input)] { return decrypt(input); });
    }
    void encryptFile(const std::string& inputPath, const std::string& outputPath) const {
        writeFile(outputPath, encrypt(readFile(inputPath)));
    }
    void decryptFile(const std::string& inputPath, const std::string& outputPath) const {
        writeFile(outputPath, decrypt(readFile(inputPath)));
    }
    std::future<void> encryptFileAsync(std::string inputPath, std::string outputPath) const {
        return std::async(std::launch::async,
                          [this, inputPath = std::move(inputPath), outputPath = std::move(outputPath)] {
                              encryptFile(inputPath, outputPath);
                          });
    }
    std::future<void> decryptFileAsync(std::string inputPath, std::string outputPath) const {
        return std::async(std::launch::async,
                          [this, inputPath = std::move(inputPath), outputPath = std::move(outputPath)] {
                              decryptFile(inputPath, outputPath);
                          });
    }

private:
    Bytes addPadding(Bytes data) const {
        const std::size_t n = cipher_->blockSize();
        const std::size_t remainder = data.size() % n;
        if (padding_ == PaddingMode::Zeros) {
            if (remainder) {
                data.resize(data.size() + n - remainder, 0);
            }
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
                for (std::size_t i = old; i + 1 < data.size(); ++i) {
                    data[i] = static_cast<std::uint8_t>(random());
                }
            }
            data.back() = static_cast<std::uint8_t>(count);
        }
        return data;
    }

    Bytes removePadding(Bytes data) const {
        if (data.empty()) {
            return data;
        }
        if (padding_ == PaddingMode::Zeros) {
            while (!data.empty() && data.back() == 0) {
                data.pop_back();
            }
            return data;
        }
        const std::size_t count = data.back();
        if (count == 0 || count > cipher_->blockSize() || count > data.size()) {
            throw std::runtime_error("Invalid padding");
        }
        if (padding_ == PaddingMode::PKCS7) {
            for (std::size_t i = data.size() - count; i < data.size(); ++i) {
                if (data[i] != count) {
                    throw std::runtime_error("Invalid PKCS7 padding");
                }
            }
        } else if (padding_ == PaddingMode::ANSI_X923) {
            for (std::size_t i = data.size() - count; i + 1 < data.size(); ++i) {
                if (data[i] != 0) {
                    throw std::runtime_error("Invalid ANSI X.923 padding");
                }
            }
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
        if (!streamMode && data.size() % n != 0) {
            throw std::invalid_argument("Ciphertext length is not block aligned");
        }
        Bytes out; out.reserve(data.size()); Bytes feedback = iv_;
        for (std::size_t offset = 0; offset < data.size(); offset += n) {
            const std::size_t count = std::min(n, data.size() - offset);
            Bytes block(data.begin() + static_cast<std::ptrdiff_t>(offset), data.begin() + static_cast<std::ptrdiff_t>(offset + count));
            Bytes result;
            if (mode_ == CipherMode::ECB) {
                result = decrypting ? cipher_->decryptBlock(block) : cipher_->encryptBlock(block);
            } else if (mode_ == CipherMode::CBC) {
                if (decrypting) {
                    result = xorBytes(cipher_->decryptBlock(block), feedback);
                    feedback = block;
                } else {
                    result = cipher_->encryptBlock(xorBytes(block, feedback));
                    feedback = result;
                }
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
                    if (count != n) {
                        feedback.assign(n, 0);
                        std::copy(block.begin(), block.end(), feedback.begin());
                    }
                } else {
                    result.resize(count);
                    for (std::size_t i = 0; i < count; ++i) {
                        result[i] = block[i] ^ mask[i];
                    }
                    if (mode_ == CipherMode::OFB) {
                        feedback = std::move(mask);
                    } else {
                        addDelta(feedback);
                    }
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

