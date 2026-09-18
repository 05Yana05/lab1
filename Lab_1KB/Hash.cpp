#include "Hash.h"
#include <sodium.h>
#include <stdexcept>

std::string Hash::hashPassword(const std::string& password) {
    if (sodium_init() < 0) {
        throw std::runtime_error("Не удалось инициализировать libsodium");
    }

    char hashed[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(
        hashed,
        password.c_str(), password.size(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE)
        != 0) {
        throw std::runtime_error("Ошибка хеширования пароля");
    }
    return std::string(hashed);
}

bool Hash::verifyPassword(const std::string& password, const std::string& stored) {
    return crypto_pwhash_str_verify(
        stored.c_str(),
        password.c_str(), password.size()) == 0;
}