#include <Common.h>
#include <Constexpr.h>
#include <resolver.h>
#include "messages.h"
#include "aes.h"

FUNC VOID Main(
    _In_ PVOID Param)
{
    STARDUST_INSTANCE

    // Step 1: Ask the user to enter a message
    std::string message = getInputFromUser("Please enter the message to encrypt:");

    if (message.empty())
    {
        showMessage("Error", "No message entered.");
        return 1;
    }

    // Step 2: Generate AES key and IV
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    if (!generateAESKey(key, iv))
    {
        showMessage("Error", "Failed to generate AES key.");
        return 1;
    }

    // Step 3: Encrypt the message
    std::string encryptedMessage = encryptMessage(message, key, iv);

    // Step 4: Display the encrypted message (in hex format)
    char encryptedMessageHex[encryptedMessage.size() * 2 + 1] = {0};
    for (size_t i = 0; i < encryptedMessage.size(); i++)
    {
        sprintf(&encryptedMessageHex[i * 2], "%02x", (unsigned char)encryptedMessage[i]);
    }
    showMessage("Encrypted Message", encryptedMessageHex);

    // Step 5: Decrypt the message
    std::string decryptedMessage = decryptMessage(encryptedMessage, key, iv);

    // Step 6: Display the decrypted message
    showMessage("Decrypted Message", decryptedMessage.c_str());

    return 0;
}