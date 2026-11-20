#include "crypto.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
namespace {

std::string toHex(const Bytes& bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result; result.reserve(bytes.size() * 2);
    for (std::uint8_t value : bytes) {
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0x0f]);
    }
    return result;
}

Bytes fromHex(const std::string& text) {
    if (text.size() % 2) {
        throw std::invalid_argument("Hex string length must be even");
    }
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') {
            return static_cast<unsigned>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<unsigned>(c - 'a' + 10);
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<unsigned>(c - 'A' + 10);
        }
        throw std::invalid_argument("Invalid hexadecimal digit");
    };
    Bytes result; result.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>((digit(text[i]) << 4) | digit(text[i + 1])));
    }
    return result;
}

std::string uppercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

CipherMode parseCipherMode(const std::string& name) {
    const std::string value = uppercase(name);
    if (value == "ECB") return CipherMode::ECB;
    if (value == "CBC") return CipherMode::CBC;
    if (value == "PCBC") return CipherMode::PCBC;
    if (value == "CFB") return CipherMode::CFB;
    if (value == "OFB") return CipherMode::OFB;
    if (value == "CTR") return CipherMode::CTR;
    if (value == "RANDOMDELTA" || value == "RANDOM_DELTA") return CipherMode::RandomDelta;
    throw std::invalid_argument("Unknown mode: " + name);
}

PaddingMode parsePaddingMode(const std::string& name) {
    const std::string value = uppercase(name);
    if (value == "ZEROS" || value == "ZERO") return PaddingMode::Zeros;
    if (value == "ANSI_X923" || value == "X923" || value == "ANSI-X923") return PaddingMode::ANSI_X923;
    if (value == "PKCS7" || value == "PKCS#7") return PaddingMode::PKCS7;
    if (value == "ISO10126" || value == "ISO_10126" || value == "ISO-10126") return PaddingMode::ISO10126;
    throw std::invalid_argument("Unknown padding: " + name);
}

std::string modeName(CipherMode mode) {
    switch (mode) {
        case CipherMode::ECB: return "ECB";
        case CipherMode::CBC: return "CBC";
        case CipherMode::PCBC: return "PCBC";
        case CipherMode::CFB: return "CFB";
        case CipherMode::OFB: return "OFB";
        case CipherMode::CTR: return "CTR";
        case CipherMode::RandomDelta: return "RandomDelta";
    }
    throw std::logic_error("Invalid cipher mode");
}

std::string paddingName(PaddingMode padding) {
    switch (padding) {
        case PaddingMode::Zeros: return "Zeros";
        case PaddingMode::ANSI_X923: return "ANSI_X923";
        case PaddingMode::PKCS7: return "PKCS7";
        case PaddingMode::ISO10126: return "ISO10126";
    }
    throw std::logic_error("Invalid padding mode");
}

Bytes pseudoRandomBytes(std::size_t count, std::mt19937& generator) {
    std::uniform_int_distribution<unsigned> distribution(0, 255);
    Bytes result(count);
    for (auto& byte : result) byte = static_cast<std::uint8_t>(distribution(generator));
    return result;
}

std::shared_ptr<ISymmetricCipher> makeCipher(const std::string& name) {
    const std::string value = uppercase(name);
    if (value == "DES") return std::make_shared<DESCipher>();
    if (value == "DEAL") return std::make_shared<DEALCipher>();
    throw std::invalid_argument("Algorithm must be DES or DEAL");
}

Bytes keyFor(const std::string& name) {
    return uppercase(name) == "DEAL"
        ? fromHex("0123456789ABCDEFFEDCBA9876543210")
        : fromHex("133457799BBCDFF1");
}

Bytes demoIv(std::size_t blockSize) {
    return blockSize == 8 ? fromHex("0102030405060708") : Bytes(blockSize, 0x01);
}

std::vector<Bytes> modeParameters(CipherMode mode, std::size_t blockSize,
                                 std::mt19937* generator = nullptr) {
    if (mode != CipherMode::RandomDelta) return {};
    Bytes delta(blockSize, 0);
    if (generator) {
        delta = pseudoRandomBytes(blockSize, *generator);
        if (std::all_of(delta.begin(), delta.end(), [](std::uint8_t b) { return b == 0; })) {
            delta.back() = 1;
        }
    } else {
        delta.back() = 3;
    }
    return {std::move(delta)};
}

bool runSelfTests() {
    const Bytes permutationInput{0xb2};
    const std::vector<std::size_t> zeroBasedPBlock{2, 0, 7, 4, 6, 1, 5, 3};
    const std::vector<std::size_t> oneBasedPBlock{3, 1, 8, 5, 7, 2, 6, 4};
    if (permuteBits(permutationInput, zeroBasedPBlock, BitOrder::LeastSignificantFirst,
                    FirstBitNumber::Zero) != Bytes{0x6c} ||
        permuteBits(permutationInput, oneBasedPBlock, BitOrder::LeastSignificantFirst,
                    FirstBitNumber::One) != Bytes{0x6c} ||
        permuteBits(permutationInput, zeroBasedPBlock, BitOrder::MostSignificantFirst,
                    FirstBitNumber::Zero) != Bytes{0xc9}) {
        std::cerr << "P-block permutation test failed\n";
        return false;
    }

    DESCipher des;
    des.setKey(fromHex("133457799BBCDFF1"));
    const Bytes desPlaintext = fromHex("0123456789ABCDEF");
    const Bytes desCiphertext = des.encryptBlock(desPlaintext);
    if (toHex(desCiphertext) != "85E813540F0AB405" || des.decryptBlock(desCiphertext) != desPlaintext) {
        std::cerr << "DES known-answer test failed\n";
        return false;
    }

    DEALKeyExpansion dealExpansion;
    for (std::size_t keySize : {std::size_t(16), std::size_t(24), std::size_t(32)}) {
        const std::size_t expectedRounds = keySize == 32 ? 8 : 6;
        if (dealExpansion.expand(Bytes(keySize, 0x2a)).size() != expectedRounds) {
            std::cerr << "DEAL key expansion returned the wrong round count\n";
            return false;
        }
        DEALCipher deal;
        deal.setKey(Bytes(keySize, static_cast<std::uint8_t>(keySize)));
        const Bytes block(16, 0x5a);
        if (deal.decryptBlock(deal.encryptBlock(block)) != block) {
            std::cerr << "DEAL round-trip failed for " << keySize * 8 << "-bit key\n";
            return false;
        }
    }

    const std::array<CipherMode, 7> modes = {CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
        CipherMode::CFB, CipherMode::OFB, CipherMode::CTR, CipherMode::RandomDelta};
    const std::array<PaddingMode, 4> paddings = {PaddingMode::Zeros, PaddingMode::ANSI_X923,
        PaddingMode::PKCS7, PaddingMode::ISO10126};
    std::mt19937 generator(0x4c414231U);
    for (const std::string& algorithm : {std::string("DES"), std::string("DEAL")}) {
        for (CipherMode mode : modes) {
            for (PaddingMode padding : paddings) {
                for (std::size_t length : {std::size_t(0), std::size_t(1), std::size_t(7),
                                           std::size_t(8), std::size_t(9), std::size_t(15), std::size_t(16),
                                           std::size_t(17), std::size_t(33)}) {
                    auto cipher = makeCipher(algorithm);
                    const std::size_t blockSize = cipher->blockSize();
                    Bytes original = pseudoRandomBytes(length, generator);
                    if (padding == PaddingMode::Zeros && !original.empty()) {
                        original.back() = 1;
                    }
                    CipherContext context(cipher, keyFor(algorithm), mode, padding,
                                          demoIv(blockSize), modeParameters(mode, blockSize, &generator));
                    const Bytes encrypted = context.encrypt(original);
                    const Bytes recovered = context.decrypt(encrypted);
                    if (recovered != original) {
                        std::cerr << algorithm << ' ' << modeName(mode) << ' '
                                  << paddingName(padding) << " failed at length " << length << '\n';
                        return false;
                    }
                }
            }
        }
    }
    std::cout << "All self-tests passed: P-block indexing, DES known-answer vector, DEAL key sizes, "
                 "7 modes, 4 paddings, and boundary lengths.\n";
    return true;
}

void printUsage(const char* executable) {
    std::cout << "Usage:\n"
              << "  " << executable << "\n"
              << "  " << executable << " --self-test\n"
              << "  " << executable << " encrypt|decrypt input-file output-file DES|DEAL MODE PADDING\n"
              << "Modes: ECB CBC PCBC CFB OFB CTR RandomDelta\n"
              << "Padding: Zeros ANSI_X923 PKCS7 ISO10126 (ignored by CFB/OFB/CTR/RandomDelta)\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
            printUsage(argv[0]);
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--self-test") {
            return runSelfTests() ? 0 : 1;
        }
        const bool fileOperation = argc >= 2 &&
            (std::string(argv[1]) == "encrypt" || std::string(argv[1]) == "decrypt");
        if (fileOperation) {
            if (argc != 7) {
                throw std::invalid_argument(
                    "file encryption/decryption requires input, output, algorithm, mode, and padding; "
                    "use the same settings for decryption");
            }
            const bool encrypting = std::string(argv[1]) == "encrypt";
            const std::string algorithm = argv[4];
            const CipherMode mode = parseCipherMode(argv[5]);
            const PaddingMode padding = parsePaddingMode(argv[6]);
            auto fileCipher = makeCipher(algorithm);
            const std::size_t blockSize = fileCipher->blockSize();
            CipherContext fileContext(fileCipher, keyFor(algorithm), mode, padding,
                                      demoIv(blockSize), modeParameters(mode, blockSize));
            if (encrypting) {
                fileContext.encryptFileAsync(argv[2], argv[3]).get();
            } else {
                fileContext.decryptFileAsync(argv[2], argv[3]).get();
            }
            std::cout << uppercase(algorithm) << '-' << modeName(mode) << '-' << paddingName(padding)
                      << (encrypting ? " encrypted " : " decrypted ")
                      << argv[2] << " -> " << argv[3] << '\n';
            return 0;
        }
        if (argc != 1) {
            printUsage(argv[0]);
            return 2;
        }

        std::mt19937 generator(0x4c414231U);
        const Bytes sample = pseudoRandomBytes(256, generator);
        const std::array<CipherMode, 7> modes = {CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
            CipherMode::CFB, CipherMode::OFB, CipherMode::CTR, CipherMode::RandomDelta};
        for (const std::string& algorithm : {std::string("DES"), std::string("DEAL")}) {
            for (CipherMode mode : modes) {
                auto cipher = makeCipher(algorithm);
                const std::size_t blockSize = cipher->blockSize();
                Bytes iv = mode == CipherMode::RandomDelta
                    ? pseudoRandomBytes(blockSize, generator) : demoIv(blockSize);
                auto extra = modeParameters(mode, blockSize,
                                            mode == CipherMode::RandomDelta ? &generator : nullptr);
                if (mode == CipherMode::RandomDelta &&
                    std::all_of(iv.begin(), iv.end(), [](std::uint8_t b) { return b == 0; })) {
                    iv.back() = 1;
                }
                CipherContext context(cipher, keyFor(algorithm), mode, PaddingMode::PKCS7,
                                      std::move(iv), std::move(extra));
                const Bytes ciphertext = context.encryptAsync(sample).get();
                const Bytes recovered = context.decryptAsync(ciphertext).get();
                std::cout << algorithm << '-' << modeName(mode) << ": "
                          << (recovered == sample ? "round-trip OK" : "ROUND-TRIP FAILED")
                          << " (" << sample.size() << " pseudo-random bytes)\n";
            }
        }
        printUsage(argv[0]);
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
