#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include <iterator>
#include <bitset>
#include <sstream>

// A basic virtual class for std::string encryption strategies.
class EncryptionStrategy
{

public:
    virtual std::string encrypt(const std::string &text, const std::string &key = "") = 0;
    virtual std::string decrypt(const std::string &text, const std::string &key = "") = 0;
};

// Concrete encryption strategy using XOR.
class XOREncryptionStrategy : public EncryptionStrategy
{
public:
    std::string encrypt(const std::string &text, const std::string &key) override
    {
        if (key.empty())
        {
            return text;
        }

        std::string output{text};

        for (size_t i = 0; i < text.size(); i++)
        {
            output[i] = text[i] ^ key[i % key.size()];
        }

        return output;
    }

    std::string decrypt(const std::string &text, const std::string &key) override
    {
        return encrypt(text, key);
    }
};

// Concrete encryption strategy using Caesar.
class CaesarEncryptionStrategy : public EncryptionStrategy
{
    const size_t ASCIISize = 255;

public:
    std::string encrypt(const std::string &text, const std::string &key) override
    {
        std::string temp{text};
        auto shift = std::stoull(key);

        for (auto &ch : temp)
        {
            ch += char(shift % ASCIISize);
        }

        return temp;
    }

    std::string decrypt(const std::string &text, const std::string &key) override
    {
        std::string temp{text};
        auto shift = std::stoull(key);

        for (auto &ch : temp)
        {
            ch -= char(shift % ASCIISize);
        }

        return temp;
    }
};

// Concrete encryption strategy using Binary code.
class BinaryEncryptionStrategy : public EncryptionStrategy
{
public:
    std::string encrypt(const std::string &text, const std::string &) override
    {
        std::stringstream temp;

        for (const auto &ch : text)
        {
            std::bitset<8> bs(static_cast<unsigned long long>(ch));
            temp << bs.to_string();
        }

        return temp.str();
    }

    std::string decrypt(const std::string &text, const std::string &) override
    {
        std::stringstream decoded;

        for (auto segmentIterator{text.begin()}; segmentIterator != text.end(); segmentIterator += 8)
        {
            std::string segment(segmentIterator, segmentIterator + 8);
            auto ASCII = std::stoull(segment, nullptr, 2);
            decoded << char(ASCII);
        }

        return decoded.str();
    }
};

// Interface for file encryption using encryption strategies.
class IFileEncryptor
{
public:
    void setStrategy(EncryptionStrategy *strat)
    {
        if (strat)
        {
            strategy = strat;
        }
    }

    bool encrypt(const std::string &filePathFrom, const std::string &filePathTo, const std::string &key = "")
    {
        if (!strategy)
            return false;

        std::ofstream output(filePathTo, std::ios::trunc);
        output << strategy->encrypt(getTextFromFile(filePathFrom), key);

        return true;
    }

    bool decrypt(const std::string &filePathFrom, const std::string &filePathTo, const std::string &key = "")
    {
        if (!strategy)
            return false;

        std::ofstream output(filePathTo, std::ios::trunc);
        output << strategy->decrypt(getTextFromFile(filePathFrom), key);

        return true;
    }

private:
    EncryptionStrategy *strategy;

    std::string getTextFromFile(const std::string &filePath)
    {
        return std::string(
            (std::istreambuf_iterator<char>(
                *(std::unique_ptr<std::ifstream>(
                      new std::ifstream(filePath)))
                     .get())),
            std::istreambuf_iterator<char>());
    }
};

int main()
{
    const std::string key{"3abc"};
    IFileEncryptor fileEncryptor;

    fileEncryptor.setStrategy(new XOREncryptionStrategy);
    fileEncryptor.encrypt(".files/XOR/XOR_Original.txt", ".files/XOR/XOR_Crypted.txt", key);
    fileEncryptor.decrypt(".files/XOR/XOR_Crypted.txt", ".files/XOR/XOR_Decrypted.txt", key);

    fileEncryptor.setStrategy(new CaesarEncryptionStrategy);
    fileEncryptor.encrypt(".files/Caesar/Caesar_Original.txt", ".files/Caesar/Caesar_Crypted.txt", key);
    fileEncryptor.decrypt(".files/Caesar/Caesar_Crypted.txt", ".files/Caesar/Caesar_Decrypted.txt", key);

    fileEncryptor.setStrategy(new BinaryEncryptionStrategy);
    fileEncryptor.encrypt(".files/Binary/Binary_Original.txt", ".files/Binary/Binary_Crypted.txt");
    fileEncryptor.decrypt(".files/Binary/Binary_Crypted.txt", ".files/Binary/Binary_Decrypted.txt");
}
