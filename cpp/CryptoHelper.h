#pragma once
#include <string>

class CryptoHelper {
public:
    // Шифрует строку алгоритмом AES-256
    static std::string encrypt(const std::string& plaintext, const std::string& key);

    // Расшифровывает строку
    static std::string decrypt(const std::string& ciphertext, const std::string& key);
};