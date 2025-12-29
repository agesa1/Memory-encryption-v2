#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <cstdint>
#include <cstring>
#include <chrono>
#include <thread>
#include <windows.h>
#include <iostream>
#include <iomanip>

namespace mem_prot {

    class SecureXOR {
    private:
        uint64_t k1, k2, k3, k4;
        uint32_t rot_val;

        inline uint64_t rotate_key(uint64_t v, uint32_t s) {
            return (v << s) | (v >> (64 - s));
        }

        inline uint64_t mix_state(uint64_t a, uint64_t b) {
            return (a ^ b) * 0x9e3779b97f4a7c15ULL;
        }

    public:
        SecureXOR() {
            auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            k1 = static_cast<uint64_t>(t) ^ 0xdeadbeefcafebabeULL;
            k2 = rotate_key(k1, 17) ^ 0x123456789abcdef0ULL;
            k3 = mix_state(k1, k2) ^ reinterpret_cast<uint64_t>(&t);
            k4 = (k1 + k2 + k3) ^ 0xfedcba9876543210ULL;
            rot_val = static_cast<uint32_t>(t & 0x1F) + 7;
        }

        void evolve() {
            k1 = rotate_key(k1, rot_val) ^ k3;
            k2 = mix_state(k2, k4);
            k3 ^= (k1 + k2);
            k4 = rotate_key(k4, (rot_val + 13) & 0x1F);
            rot_val = ((rot_val * 31) + 17) & 0x1F;
        }

        void process_block(void* data, size_t sz) {
            uint8_t* ptr = static_cast<uint8_t*>(data);
            uint64_t keys[] = { k1, k2, k3, k4 };

            for (size_t i = 0; i < sz; ++i) {
                uint64_t active_key = keys[i & 3];
                active_key = rotate_key(active_key, (i * rot_val) & 0x3F);
                ptr[i] ^= static_cast<uint8_t>((active_key >> ((i & 7) * 8)) & 0xFF);

                if ((i & 0xF) == 0xF) evolve();
            }
        }
    };

    template<typename T>
    class ProtectedValue {
    private:
        uint8_t encrypted_data[sizeof(T) + 16];
        uint64_t k1, k2, k3;

        void xor_data(uint8_t* data, size_t sz) {
            for (size_t i = 0; i < sz; ++i) {
                uint64_t key = (i % 3 == 0) ? k1 : (i % 3 == 1) ? k2 : k3;
                key = (key << (i & 15)) | (key >> (64 - (i & 15)));
                data[i] ^= static_cast<uint8_t>((key >> ((i & 7) * 8)) & 0xFF);
            }
        }

    public:
        ProtectedValue(const T& val) {
            auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            k1 = static_cast<uint64_t>(t) ^ 0xDEADBEEFCAFEBABEULL;
            k2 = (k1 * 0x9E3779B97F4A7C15ULL) ^ 0x123456789ABCDEF0ULL;
            k3 = (k1 ^ k2) + 0xFEDCBA9876543210ULL;

            uint8_t temp[sizeof(T)];
            std::memcpy(temp, &val, sizeof(T));
            xor_data(temp, sizeof(T));
            std::memcpy(encrypted_data, temp, sizeof(T));
        }

        T get() {
            uint8_t temp[sizeof(T)];
            std::memcpy(temp, encrypted_data, sizeof(T));

            std::cout << "DEC: ";
            for (size_t i = 0; i < sizeof(T) && i < 8; ++i) {
                std::cout << std::hex << (int)temp[i] << " ";
            }

            xor_data(temp, sizeof(T));

            std::cout << "-> ";
            for (size_t i = 0; i < sizeof(T) && i < 8; ++i) {
                std::cout << std::hex << (int)temp[i] << " ";
            }
            std::cout << std::dec << std::endl;

            T result;
            std::memcpy(&result, temp, sizeof(T));
            std::memset(temp, 0, sizeof(T));
            return result;
        }

        void set(const T& val) {
            uint8_t temp[sizeof(T)];
            std::memcpy(temp, &val, sizeof(T));

            std::cout << "ENC: ";
            for (size_t i = 0; i < sizeof(T) && i < 8; ++i) {
                std::cout << std::hex << (int)temp[i] << " ";
            }

            xor_data(temp, sizeof(T));

            std::cout << "-> ";
            for (size_t i = 0; i < sizeof(T) && i < 8; ++i) {
                std::cout << std::hex << (int)temp[i] << " ";
            }
            std::cout << std::dec << std::endl;

            std::memcpy(encrypted_data, temp, sizeof(T));
            std::memset(temp, 0, sizeof(T));
        }
    };

    class StackGuard {
    private:
        uint64_t k1, k2, k3;

    public:
        StackGuard() {
            auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            k1 = static_cast<uint64_t>(t) ^ 0xA5A5A5A5A5A5A5A5ULL;
            k2 = reinterpret_cast<uint64_t>(_ReturnAddress()) ^ 0x5A5A5A5A5A5A5A5AULL;
            k3 = (k1 * k2) ^ 0xF0F0F0F0F0F0F0F0ULL;
        }

        bool verify() {
            uint64_t check = (k1 * k2) ^ 0xF0F0F0F0F0F0F0F0ULL;
            return check == k3;
        }
    };

    class TLSProtector {
    private:
        DWORD tls_index;
        uint64_t k1, k2;

        void xor_buffer(uint8_t* data, size_t sz) {
            for (size_t i = 0; i < sz; ++i) {
                uint64_t key = (i & 1) ? k2 : k1;
                data[i] ^= static_cast<uint8_t>((key >> ((i & 7) * 8)) & 0xFF);
            }
        }

    public:
        TLSProtector() {
            tls_index = TlsAlloc();
            auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            k1 = static_cast<uint64_t>(t) ^ 0xFEDCBA9876543210ULL;
            k2 = (k1 >> 17) ^ 0x0123456789ABCDEFULL;
        }

        ~TLSProtector() {
            if (tls_index != TLS_OUT_OF_INDEXES) {
                void* ptr = TlsGetValue(tls_index);
                if (ptr) delete[] static_cast<uint8_t*>(ptr);
                TlsFree(tls_index);
            }
        }

        void store_encrypted(void* data, size_t sz) {
            uint8_t* buffer = new uint8_t[sz];
            std::memcpy(buffer, data, sz);
            xor_buffer(buffer, sz);
            TlsSetValue(tls_index, buffer);
        }

        bool retrieve_decrypted(void* out, size_t sz) {
            uint8_t* buffer = static_cast<uint8_t*>(TlsGetValue(tls_index));
            if (!buffer) return false;

            uint8_t* temp = new uint8_t[sz];
            std::memcpy(temp, buffer, sz);
            xor_buffer(temp, sz);
            std::memcpy(out, temp, sz);
            delete[] temp;
            return true;
        }
    };

    inline void secure_memzero(void* ptr, size_t sz) {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        while (sz--) *p++ = 0;
    }

}

#endif
