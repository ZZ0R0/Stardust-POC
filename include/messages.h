#ifndef MESSAGES_H
#define MESSAGES_H

#include <string>

#ifdef __cplusplus
extern "C"
{
#endif

    FUNC std::string getInputFromUser(const char *prompt);
    FUNC void showMessage(const std::string &title, const std::string &message);

#ifdef __cplusplus
}
#endif

#endif // MESSAGES_H
