#include <Common.h>
#include <Constexpr.h>
#include <messages.h>
#include <iostream>
#include <string>

// Function to display a message box and get user input
FUNC std::string getInputFromUser(const char *prompt)
{
    STARDUST_INSTANCE

    char input[256] = {0};
    if (Instance()->Win32.MessageBoxA(nullptr, prompt, "Enter Message", MB_OKCANCEL) == IDOK)
    {
        Instance()->Win32.MessageBoxA(nullptr, "Please enter your message in the console", "Message Entry", MB_OK);
        std::cout << "Enter your message: ";
        std::cin.getline(input, sizeof(input));
    }
    return std::string(input);
}

// Function to display a message box with text
FUNC void showMessage(const std::string &title, const std::string &message)
{
    STARDUST_INSTANCE
    Instance()->Win32.MessageBoxA(nullptr, message.c_str(), title.c_str(), MB_OK);
}
