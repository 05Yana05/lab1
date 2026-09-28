#include "Validator.h"
#include <iostream>
#include <cctype>
#include <regex>

using namespace std;

// Проверка логина: не пустой, минимум 3 символа, без клавиатурных последовательностей
bool Validator::validateUsername(const std::string& username) {
    if (username.empty()) {
        cout << "Username cannot be empty\n";
        return false;
    }
    if (utf8_length(username) < 3) {
        cout << "Username must be at least 3 characters\n";
        return false;
    }
    if (containsKeyboardPattern(username)) {
        cout << "Username contains an obvious keyboard pattern\n";
        return false;
    }
    return true;
}

// Проверка пароля: не пустой, без клавиатурных последовательностей,
// без трёх одинаковых символов подряд, без года
bool Validator::validatePassword(const string& password) {
    if (password.empty()) {
        cout << "Password cannot be empty\n";
        return false;
    }
    if (containsKeyboardPattern(password)) {
        cout << "Password contains an obvious keyboard pattern\n";
        return false;
    }
    if (hasRepeatedChars(password)) {
        cout << "Password contains three identical characters in a row\n";
        return false;
    }
    if (containsYear(password)) {
        cout << "Password contains a year - too predictable\n";
        return false;
    }
    return true;
}

// Проверка, что два пароля совпадают
bool Validator::validatePasswordMatch(const string& password, const string& confirmPassword) {
    if (password != confirmPassword) {
        cout << "Passwords do not match\n";
        return false;
    }
    return true;
}

// Проверка, что логин не зарезервирован (admin, root и т.д.)
bool Validator::isReservedUsername(const string& username) {
    string reserved[] = { "admin", "root", "system", "user", "test" };
    for (const string& reservedName : reserved) {
        if (username == reservedName) {
            cout << "Username '" << reservedName << "' is reserved\n";
            return true;
        }
    }
    return false;
}

// Поиск клавиатурных последовательностей: qwerty, asdf, zxcvbn и т.п.
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

// Поиск трёх одинаковых символов подряд через регулярное выражение
bool Validator::hasRepeatedChars(const std::string& input) {
    // (.) - любой символ, запоминаем как группу 1
    // \1\1 - ещё два таких же символа
    static const std::regex re(R"((.)\1\1)");
    return std::regex_search(input, re);
}

// Поиск года (1900-2099) в любом месте пароля
bool Validator::containsYear(const std::string& input) {
    // Без \b - границы слова не работают, если рядом с годом
    // стоят буквы, цифры или подчёркивания
    static const std::regex re(R"((19|20)\d{2})");
    return std::regex_search(input, re);
}

// Подсчёт Unicode-символов (code points) в UTF-8 строке
size_t Validator::utf8_length(const std::string& input) {
    size_t count = 0;
    for (unsigned char c : input) {
        // Считаем только байты, которые НЕ являются continuation-байтами
        // (continuation-байты начинаются с битов 10)
        if ((c & 0xC0) != 0x80) {
            ++count;
        }
    }
    return count;
}