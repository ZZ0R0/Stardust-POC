#ifndef AES_H
#define AES_H

#include <Common.h>
#include <Constexpr.h>
#include <string>

#ifdef __cplusplus
extern "C"
{
#endif

    FUNC bool generateAESKey(unsigned char *key, unsigned char *iv);
    FUNC std::string encryptMessage(const std::string &message, const unsigned char *key, const unsigned char *iv);
    FUNC std::string decryptMessage(const std::string &encryptedMessage, const unsigned char *key, const unsigned char *iv);

#ifdef __cplusplus
}
#endif

#endif // AES_H
