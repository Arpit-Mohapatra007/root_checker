#ifndef XORSTR_H
#define XORSTR_H

#include <array>
#include <stddef.h>

constexpr unsigned long long int XorSeed(int index, int seed) {
    return (static_cast<unsigned long long int>(seed) ^ index) * 0x7FEB352D;
}

template <typename T, size_t N, int Seed>
struct XorString {
    std::array<T, N> encrypted_buffer;

    constexpr XorString(const T (&str)[N]) : encrypted_buffer{} {
        for (size_t i = 0; i < N; ++i) {
            encrypted_buffer[i] = str[i] ^ static_cast<T>(XorSeed(i, Seed) & 0xFF);
        }
    }

   void decrypt(char (&out)[N]) const {
        for (size_t i = 0; i < N; ++i) {
            out[i] = encrypted_buffer[i] ^ static_cast<T>(XorSeed(i, Seed) & 0xFF);
        }
    }
};

#define XOR(str) ([&]() { \
    constexpr size_t N = sizeof(str); \
    static constexpr auto xor_str = XorString<char, N, __LINE__ + 0x55>(str); \
    struct Buf { char data[N]; } buf; \
    xor_str.decrypt(buf.data); \
    return buf; \
}().data)

#endif