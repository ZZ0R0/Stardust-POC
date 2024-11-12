# Stardust-POC

An POC to try features of Stardust framework which makes it easier to code PIC code from C and compiling to shellcode

I've implemented a resolver that will setup the STARDUST_INSTANCE to load all functions from external libraries 

Example with OpenSSL's libcrypto for simple AES implementation

```cpp
#include <resolver.h>
#include <Common.h>
#include <Constexpr.h>
#pragma comment(lib, "libcrypto.lib") // Only libcrypto is needed for AES operations

FUNC VOID Import()
{
    STARDUST_INSTANCE

    // resolve kernel32.dll related functions
    if ((Instance()->Modules.Kernel32 = LdrModulePeb(H_MODULE_KERNEL32)))
    {
        if (!(Instance()->Win32.LoadLibraryW = LdrFunction(Instance()->Modules.Kernel32, HASH_STR("LoadLibraryW"))))
        {
            return;
        }
    }

    // Function to hash a string
    if ((Instance()->Modules.User32 = Instance()->Win32.LoadLibraryW(L"User32")))
    {
        if (!(Instance()->Win32.MessageBoxA = LdrFunction(Instance()->Modules.User32, HASH_STR("MessageBoxA"))))
        {
            return;
        }
    }

    // Loading AES related functions from libcrypto
    if ((Instance()->Modules.libcrypto = Instance()->Win32.LoadLibraryW(L"libcrypto")))
    {
        if (!(Instance()->Win32.AES_set_encrypt_key = LdrFunction(Instance()->Modules.libcrypto, HASH_STR("AES_set_encrypt_key"))) ||
            !(Instance()->Win32.AES_set_decrypt_key = LdrFunction(Instance()->Modules.libcrypto, HASH_STR("AES_set_decrypt_key"))) ||
            !(Instance()->Win32.AES_cbc_encrypt = LdrFunction(Instance()->Modules.libcrypto, HASH_STR("AES_cbc_encrypt"))) ||
            !(Instance()->Win32.RAND_bytes = LdrFunction(Instance()->Modules.libcrypto, HASH_STR("RAND_bytes"))))
        {
            return; // Handle function loading failure
        }
    }
}
```

Once the functions are resolved inside the instance we can then call them inside the relevant file using the instance identifier

```cpp
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
``` 

I'm missing from now most of the logic of the framework

For example I don't know how to load external libs types into the instance like "AES_KEY" for example

I'm also not sure if I can call my project's function without passing through the instance

And finally but most importantly I don't know if i can use externall cpp inside the stardust framework ...

Most is still to be done yet !

Original [Blog post](https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/) by C5pider.
