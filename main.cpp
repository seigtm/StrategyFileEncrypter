#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include <bitset>
#include <sstream>

class EncryptionStrategy {

public:
    virtual std::string encrypt(const std::string& text, const std::string& key = "") = 0;
    virtual std::string decrypt(const std::string& text, const std::string& key = "") = 0;
};


class XOREncryptionStrategy : public EncryptionStrategy {

public:
    std::string encrypt(const std::string& text, const std::string& key) override {
        if (key.empty()) {
            return text;
        }

        std::string output = text;

        for (size_t i = 0; i < text.size(); i++)
            output[i] = text[i] ^ key[i % key.size()];

        return output;
    }

    std::string decrypt(const std::string& text, const std::string& key) override {
        return encrypt(text, key);
    }
};

class CaesarEncryptionStrategy : public EncryptionStrategy {

    const size_t ASCIISize = 255;

public:
    std::string encrypt(const std::string& text, const std::string& key) override {
        std::string temp{ text };
        auto shift = std::stoull(key);

        for (auto& ch : temp) {
            ch += char(shift % ASCIISize);
        }

        return temp;
    }

    std::string decrypt(const std::string& text, const std::string& key) override {
        std::string temp{ text };
        auto shift = std::stoull(key);

        for (auto& ch : temp) {
            ch -= char(shift % ASCIISize);
        }

        return temp;
    }
};

class BinaryEncryptionStrategy : public EncryptionStrategy {

public:
    std::string encrypt(const std::string& text, const std::string&) override {
        std::stringstream temp;

        for (const auto &ch : text) {
            std::bitset<8> bs(static_cast<unsigned long long>(ch));
            temp << bs.to_string();
        }

        return temp.str();
    }

    std::string decrypt(const std::string& text, const std::string&) override {
        std::stringstream decoded;

        for (auto segmentIterator{ text.begin() }; segmentIterator != text.end(); segmentIterator += 8) {
            std::string segment(segmentIterator, segmentIterator + 8);
            auto ASCII = std::stoull(segment, nullptr, 2);
            decoded << char(ASCII);
        }

        return decoded.str();
    }
};


class FileCryptingInterface {

public:
    // FileCryptingInterface() = default;

    void setStrategy(EncryptionStrategy* strat) {
        if (strat)
            strategy = strat;
    }

    std::string encrypt(const std::string& text, const std::string& key = "") {
        return strategy ? strategy->encrypt(text, key) : text;
    }

    std::string decrypt(const std::string& text, const std::string& key = "") {
        return strategy ? strategy->decrypt(text, key) : text;
    }

private:
    EncryptionStrategy* strategy;
};

int main() {
    std::string text = "abc";
    std::string key = "4";

    FileCryptingInterface fileCrypter;

    std::cout << "XOR:" << std::endl;
    fileCrypter.setStrategy(new XOREncryptionStrategy);
    std::cout << fileCrypter.encrypt(text, key) << std::endl;
    std::cout << fileCrypter.decrypt("UVW", key) << std::endl << std::endl;

    std::cout << "Caesar:" << std::endl;
    fileCrypter.setStrategy(new CaesarEncryptionStrategy);
    std::cout << fileCrypter.encrypt(text, key) << std::endl;
    std::cout << fileCrypter.decrypt("efg", key) << std::endl << std::endl;

    std::cout << "Binary:" << std::endl;
    fileCrypter.setStrategy(new BinaryEncryptionStrategy);
    std::cout << fileCrypter.encrypt(text, "") << std::endl;
    std::cout << fileCrypter.decrypt("011000010110001001100011", "") << std::endl;
}
