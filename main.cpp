#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include <iterator>
#include <bitset>
#include <sstream>

/** @brief A basic virtual class for std::string encryption strategies. */
class EncryptionStrategy
{
public:
    /**
     * @brief Pure virtual text (std::string) encryption method.
     * 
     * @param text text to encrypt.
     * @param key key string, empty by default.
     * @return encrypted text.
     */
    virtual std::string encrypt(const std::string &text, const std::string &key = "") = 0;

    /**
     * @brief Pure virtual text (std::string) decryption method.
     * 
     * @param text text to decrypt.
     * @param key key string, empty by default.
     * @return decrypted text.
     */
    virtual std::string decrypt(const std::string &text, const std::string &key = "") = 0;
};

/** @brief Concrete encryption strategy using XOR. 
 * Inherted from the base virtual class EncryptionStrategy. */
class XOREncryptionStrategy : public EncryptionStrategy
{
public:
    /**
     * @brief Text (std::string) encryption method using XOR.
     * 
     * @param text text to encrypt.
     * @param key key string.
     * @return encrypted text by XOR.
     */
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

    /**
     * @brief Text (std::string) decryption method using XOR.
     * 
     * @param text text to decrypt.
     * @param key key string.
     * @return decrypted text by XOR.
     */
    std::string decrypt(const std::string &text, const std::string &key) override
    {
        return encrypt(text, key);
    }
};

/**
 * @brief Concrete encryption strategy using Caesar. 
 * Inherted from the base virtual class EncryptionStrategy.
 */
class CaesarEncryptionStrategy : public EncryptionStrategy
{
    const size_t ASCIISize = 255;

public:
    /**
     * @brief Text (std::string) encryption method using Caesar.
     * 
     * @param text text to encrypt.
     * @param key key string.
     * @return encrypted text by Caesar.
     */
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

    /**
     * @brief Text (std::string) decryption method using Caesar.
     * 
     * @param text text to decrypt.
     * @param key key string.
     * @return decrypted text by Caesar.
     */
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

/** @brief Concrete encryption strategy using Binary code. 
 * Inherted from the base virtual class EncryptionStrategy. */
class BinaryEncryptionStrategy : public EncryptionStrategy
{
public:
    /**
     * @brief Text (std::string) encryption method using Binary code.
     * 
     * @param text text to encrypt.
     * @return encrypted text by Binary code.
     */
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

    /**
     * @brief Text (std::string) decryption method using Binary code.
     * 
     * @param text text to decrypt.
     * @return decrypted text by Binary code.
     */
    std::string decrypt(const std::string &text, const std::string &) override
    {
        std::stringstream decoded;

        for (std::string::const_iterator segmentIterator{text.begin()}; segmentIterator != text.end(); segmentIterator += 8)
        {
            std::string segment(segmentIterator, segmentIterator + 8);
            auto ASCII = std::stoull(segment, nullptr, 2);
            decoded << char(ASCII);
        }

        return decoded.str();
    }
};

/** @brief Interface for file encryption using text encryption strategies. */
class IFileEncryptor
{
public:
    /**
     * @brief Set the Strategy object.
     * 
     * @param strat strategy object to encrypt/decrypt with.
     */
    void setStrategy(EncryptionStrategy *strat)
    {
        if (strat)
        {
            strategy = strat;
        }
    }

    /**
     * @brief Text files encryption method.
     * 
     * @param filePathFrom path to the file from which the text is taken for encryption.
     * @param filePathTo path to the file to which the ecrypted text will be written.
     * @param key key string, empty by default.
     * @return true if the encryption strategy object was initialized earlier and false otherwise.
     */
    bool encrypt(const std::string &filePathFrom, const std::string &filePathTo, const std::string &key = "")
    {
        if (!strategy)
            return false;

        std::ofstream output(filePathTo, std::ios::trunc);
        output << strategy->encrypt(getTextFromFile(filePathFrom), key);

        return true;
    }

    /**
     * @brief Text files decryption method.
     * 
     * @param filePathFrom path to the file from which the text is taken for decryption.
     * @param filePathTo path to the file to which the decrypted text will be written.
     * @param key key string, empty by default.
     * @return true if the encryption strategy object was initialized earlier and false otherwise.
     */
    bool decrypt(const std::string &filePathFrom, const std::string &filePathTo, const std::string &key = "")
    {
        if (!strategy)
            return false;

        std::ofstream output(filePathTo, std::ios::trunc);
        output << strategy->decrypt(getTextFromFile(filePathFrom), key);

        return true;
    }

private:
    /** @brief Text encryption strategy object. */
    EncryptionStrategy *strategy;

    /**
     * @brief Get the text from file object.
     * 
     * @param filePath path to text file.
     * @return std::string (text from file).
     */
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
