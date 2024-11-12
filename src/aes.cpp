#include "aes.h"
#include <Common.h>
#include <Constexpr.h>
#include <vector>
#include <sstream>
#include <string>

// Function to generate a random AES key and IV
FUNC bool generateAESKey(unsigned char *key, unsigned char *iv)
{
    STARDUST_INSTANCE
    if (!Instance()->Win32.RAND_bytes(key, AES_BLOCK_SIZE) || !Instance()->Win32.RAND_bytes(iv, AES_BLOCK_SIZE))
    {
        return false; // Failed to generate random bytes
    }
    return true;
}

// Function to encrypt a message using AES
FUNC std::string encryptMessage(const std::string &message, const unsigned char *key, const unsigned char *iv)
{
    STARDUST_INSTANCE
    AES_KEY encryptKey;
    Instance()->Win32.AES_set_encrypt_key(key, 128, &encryptKey);

    // Padding to ensure block size compatibility
    std::string paddedMessage = message;
    while (paddedMessage.size() % AES_BLOCK_SIZE != 0)
    {
        paddedMessage += ' ';
    }

    std::vector<unsigned char> encryptedMessage(paddedMessage.size());
    for (size_t i = 0; i < paddedMessage.size(); i += AES_BLOCK_SIZE)
    {
        Instance()->Win32.AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(&paddedMessage[i]),
                                          &encryptedMessage[i], AES_BLOCK_SIZE, &encryptKey, const_cast<unsigned char *>(iv), AES_ENCRYPT);
    }

    return std::string(encryptedMessage.begin(), encryptedMessage.end());
}

// Function to decrypt a message using AES
FUNC std::string decryptMessage(const std::string &encryptedMessage, const unsigned char *key, const unsigned char *iv)
{
    STARDUST_INSTANCE
    AES_KEY decryptKey;
    Instance()->Win32.AES_set_decrypt_key(key, 128, &decryptKey);

    std::vector<unsigned char> decryptedMessage(encryptedMessage.size());
    for (size_t i = 0; i < encryptedMessage.size(); i += AES_BLOCK_SIZE)
    {
        Instance()->Win32.AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(&encryptedMessage[i]),
                                          &decryptedMessage[i], AES_BLOCK_SIZE, &decryptKey, const_cast<unsigned char *>(iv), AES_DECRYPT);
    }

    // Remove padding
    std::string result = std::string(decryptedMessage.begin(), decryptedMessage.end());
    result.erase(result.find_last_not_of(" ") + 1); // Trim spaces from padding
    return result;
}
