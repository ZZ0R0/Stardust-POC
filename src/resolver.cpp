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