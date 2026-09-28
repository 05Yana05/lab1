#include "catch_amalgamated.hpp"
#include "Validator.h"
#include "Hash.h"

// ============== Тесты для Validator::validateUsername ==============

// Логин короче 3 символов отклоняется
TEST_CASE("Username too short") {
    REQUIRE_FALSE(Validator::validateUsername("ab"));
    REQUIRE_FALSE(Validator::validateUsername("a"));
}

// Логин ровно из 3 символов проходит
TEST_CASE("Username exactly 3 chars passes") {
    REQUIRE(Validator::validateUsername("abc"));
}

// Кириллица в логине проходит (проверка utf8_length)
TEST_CASE("Cyrillic username passes") {
    REQUIRE(Validator::validateUsername("Алиса"));
}

// Клавиатурные последовательности в логине отклоняются
TEST_CASE("Username with keyboard pattern rejected") {
    REQUIRE_FALSE(Validator::validateUsername("qwerty"));
    REQUIRE_FALSE(Validator::validateUsername("qwerty123"));
    REQUIRE_FALSE(Validator::validateUsername("asdfgh"));
}

// Зарезервированные логины распознаются
TEST_CASE("Reserved usernames") {
    REQUIRE(Validator::isReservedUsername("admin"));
    REQUIRE(Validator::isReservedUsername("root"));
    REQUIRE(Validator::isReservedUsername("system"));
    REQUIRE(Validator::isReservedUsername("user"));
    REQUIRE(Validator::isReservedUsername("test"));
    REQUIRE_FALSE(Validator::isReservedUsername("alice"));
}

// ============== Тесты для Validator::validatePassword ==============

// Пустой пароль отклоняется
TEST_CASE("Empty password rejected") {
    REQUIRE_FALSE(Validator::validatePassword(""));
}

// Нормальный пароль проходит
TEST_CASE("Normal password passes") {
    REQUIRE(Validator::validatePassword("MyUniquePass123"));
}

// Клавиатурные последовательности в пароле отклоняются
TEST_CASE("Password with keyboard pattern rejected") {
    REQUIRE_FALSE(Validator::validatePassword("qwerty123"));
    REQUIRE_FALSE(Validator::validatePassword("123456"));
    REQUIRE_FALSE(Validator::validatePassword("zxcvbnm"));
}

// Три одинаковых символа подряд отклоняются
TEST_CASE("Password with repeated chars rejected") {
    REQUIRE_FALSE(Validator::validatePassword("aaaSecret"));
    REQUIRE_FALSE(Validator::validatePassword("Pass111word"));
    REQUIRE_FALSE(Validator::validatePassword("test!!!pass"));
}

// Год в пароле отклоняется (проверка регулярки)
TEST_CASE("Password with year rejected") {
    REQUIRE_FALSE(Validator::validatePassword("Secret_1990"));
    REQUIRE_FALSE(Validator::validatePassword("2024_Password"));
}

// ============== Тесты для Validator::utf8_length ==============

// ASCII: 1 символ = 1 байт
TEST_CASE("utf8_length for ASCII") {
    REQUIRE(Validator::utf8_length("abc") == 3);
    REQUIRE(Validator::utf8_length("hello") == 5);
    REQUIRE(Validator::utf8_length("") == 0);
}

// Кириллица: 1 символ = 2 байта в UTF-8
TEST_CASE("utf8_length for Cyrillic") {
    REQUIRE(Validator::utf8_length("Алиса") == 5);
    REQUIRE(Validator::utf8_length("я") == 1);
    REQUIRE(Validator::utf8_length("абв") == 3);
}

// ============== Тесты для Hash (Argon2id) ==============

// Правильный пароль проверяется успешно
TEST_CASE("Hash verifies correct password") {
    std::string h = Hash::hashPassword("MySecretPass123");
    REQUIRE(Hash::verifyPassword("MySecretPass123", h));
}

// Неправильный пароль отвергается
TEST_CASE("Hash rejects wrong password") {
    std::string h = Hash::hashPassword("MySecretPass123");
    REQUIRE_FALSE(Hash::verifyPassword("WrongPass", h));
}

// Два хеша одного пароля разные (из-за случайной соли)
TEST_CASE("Different hashes for same password") {
    std::string h1 = Hash::hashPassword("SamePassword");
    std::string h2 = Hash::hashPassword("SamePassword");
    REQUIRE(h1 != h2);
    REQUIRE(Hash::verifyPassword("SamePassword", h1));
    REQUIRE(Hash::verifyPassword("SamePassword", h2));
}