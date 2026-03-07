#ifndef XORSTR_H
#define XORSTR_H

#define XORSTR_SEED ((__TIME__[7] - '0') * 1  + (__TIME__[6] - '0') * 10  + \
                     (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 + \
                     (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)

#define XOR(str) ([]() noexcept -> const char* { \
    constexpr auto len = sizeof(str) / sizeof(str[0]); \
    constexpr auto key = static_cast<unsigned char>(XORSTR_SEED + __LINE__); \
    static char encrypted[len]; \
    static bool init = false; \
    if (!init) { \
        for (size_t i = 0; i < len - 1; ++i) { \
            encrypted[i] = str[i] ^ (key + static_cast<unsigned char>(i)); \
        } \
        encrypted[len - 1] = '\0'; \
        init = true; \
    } \
    static thread_local char decrypted[len]; \
    for (size_t i = 0; i < len - 1; ++i) { \
        decrypted[i] = encrypted[i] ^ (key + static_cast<unsigned char>(i)); \
    } \
    decrypted[len - 1] = '\0'; \
    return decrypted; \
}())

#endif 