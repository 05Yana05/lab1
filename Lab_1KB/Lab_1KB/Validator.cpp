#include "Validator.h"
#include <iostream>
#include <cctype>
#include <regex>

using namespace std;

bool Validator::validateUsername(const std::string& username) {
    if (username.empty()) {
        cout << "Логин не может быть пустым\n";
        return false;
    }
    if (utf8_length(username) < 3) {
        cout << "Логин должен содержать минимум 3 символа\n";
        return false;
    }
    if (containsKeyboardPattern(username)) {
        cout << "Логин содержит очевидную клавиатурную последовательность\n";
        return false;
    }
    return true;
}

bool Validator::validatePassword(const string& password) {
    if (password.empty()) {
        cout << "Пароль не может быть пустым\n";
        return false;
    }
    if (containsKeyboardPattern(password)) {
        cout << "Пароль содержит очевидную клавиатурную последовательность\n";
        return false;
    }
    if (hasRepeatedChars(password)) {
        cout << "Пароль содержит три одинаковых символа подряд\n";
        return false;
    }
    if (containsYear(password)) {
        cout << "Пароль содержит год — это слишком предсказуемо\n";
        return false;
    }
    return true;
}

bool Validator::validatePasswordMatch(const string& password, const string& confirmPassword) {
    if (password != confirmPassword) {
        cout << "Пароли не совпадают\n";
        return false;
    }
    return true;
}

bool Validator::isReservedUsername(const string& username) {
    string reserved[] = { "admin", "root", "system", "user", "test" };
    for (const string& reservedName : reserved) {
        if (username == reservedName) {
            cout << "Логин '" << reservedName << "' зарезервирован\n";
            return true;
        }
    }
    return false;
}

bool Validator::containsKeyboardPattern(const std::string& input) {
    if (input.empty()) return false;

    // Приводим к нижнему регистру для сравнения
    std::string lower = input;
    for (char& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    // Известные клавиатурные последовательности
    static const char* patterns[] = {
        // Верхний ряд QWERTY
        "qwertyuiop", "qwerty", "qwert", "werty",
        // Средний ряд ASDF
        "asdfghjkl", "asdfgh", "asdf", "sdfg",
        // Нижний ряд ZXCVB
        "zxcvbnm", "zxcvbn", "zxcvb", "xcvbn",
        // Цифры
        "1234567890", "123456789", "12345678",
        "1234567", "123456", "12345",
        // Диагонали
        "1qaz2wsx", "qazwsx", "1q2w3e", "1q2w3e4r",
        "q1w2e3", "q1w2e3r4",
        // Лесенки
        "1qaz", "2wsx", "3edc", "4rfv",
        "zaq1", "xsw2", "cde3", "vfr4",
        // Частые короткие
        "qqq", "www", "eee", "aaa", "zzz", "111", "000"
    };

    for (const char* pattern : patterns) {
        if (lower.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool Validator::hasRepeatedChars(const std::string& input) {
    // Ловит три и более одинаковых символа подряд: aaa, 111, !!!
    // (.)  — любой символ, запоминаем его как группу №1
    // \1\1 — ещё два таких же символа
    static const std::regex re(R"((.)\1\1)");
    return std::regex_search(input, re);
}

bool Validator::containsYear(const std::string& input) {
    // Ловит год от 1900 до 2099 как отдельное слово
    // \b      — граница слова
    // (19|20) — 19 или 20
    // \d{2}   — две цифры
    // \b      — граница слова
    static const std::regex re(R"(\b(19|20)\d{2}\b)");
    return std::regex_search(input, re);
}

size_t Validator::utf8_length(const std::string& input) {
    size_t count = 0;
    for (unsigned char c : input) {
        if ((c & 0xC0) != 0x80) {
            ++count;
        }
    }
    return count;
}