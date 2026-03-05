#ifndef XORSTR_H
#define XORSTR_H

#include <string>
#include <array>
#include <utility>

constexpr unsigned long long int XorSeed(int index, int seed){
    return (static_cast<unsigned long long int>(seed) ^ index) * 0x7FEB352D;
}

template <typename T, size_t N, int Seed>
struct XorString{
    std::array<T, N> encrypted_buffer;
    constexpr XorString(const T(&str)[N]) : encrypted_buffer{} {
        for (size_t i = 0; i < N; ++i) {
            encrypted_buffer[i] = str[i] ^ static_cast<T>(XorSeed(i, Seed) & 0xFF);
        }
    }

    struct DecryptedWrapper{
        char buffer[N];

        DecryptedWrapper(const std::array<T, N>& encrypted_buffer) {
            for (size_t i = 0; i < N; ++i) {
                buffer[i] = encrypted_buffer[i] ^ static_cast<T>(XorSeed(i, Seed) & 0xFF);
            }
        }

        const char* get() const {
            return buffer;
        }
    };

    DecryptedWrapper decrypt() const {
        return DecryptedWrapper(encrypted_buffer);
    }
};

#define XOR(str) ([]() -> const char* { \
    constexpr size_t N = sizeof(str); \
    static auto xor_str = XorString<char, N, __LINE__ + 0x55>(str); \
    static char buffer[N]; \
    static bool decrypted = false; \
    if (!decrypted) { \
        auto wrapper = xor_str.decrypt(); \
        for(size_t i=0; i<N; i++) buffer[i] = wrapper.buffer[i]; \
        decrypted = true; \
    } \
    return buffer; \
}())

#endif