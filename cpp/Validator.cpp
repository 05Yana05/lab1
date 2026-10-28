#include "Validator.h"
#include <iostream>
#include <cctype>
#include <regex>

using namespace std;

// Преобразование результата в текст
string validationMessage(ValidationResult result) {
    switch (result) {
    case ValidationResult::Ok:              return "";
    case ValidationResult::Empty:           return "Поле не может быть пустым";
    case ValidationResult::TooShort:        return "Логин должен быть не короче 3 символов";
    case ValidationResult::KeyboardPattern: return "Содержит очевидную клавиатурную последовательность";
    case ValidationResult::RepeatedChars:   return "Содержит три одинаковых символа подряд";
    case ValidationResult::ContainsYear:    return "Содержит год — слишком предсказуемо";
    case ValidationResult::Reserved:        return "Этот логин зарезервирован";
    case ValidationResult::Mismatch:        return "Пароли не совпадают";
    }
    return "Неизвестная ошибка";
}

ValidationResult Validator::validateUsername(const std::string& username) {
    if (username.empty()) return ValidationResult::Empty;
    if (utf8_length(username) < 3) return ValidationResult::TooShort;
    if (containsKeyboardPattern(username)) return ValidationResult::KeyboardPattern;
    if (isReservedUsername(username)) return ValidationResult::Reserved;
    return ValidationResult::Ok;
}

ValidationResult Validator::validatePassword(const string& password) {
    if (password.empty()) return ValidationResult::Empty;
    if (containsKeyboardPattern(password)) return ValidationResult::KeyboardPattern;
    if (hasRepeatedChars(password)) return ValidationResult::RepeatedChars;
    if (containsYear(password)) return ValidationResult::ContainsYear;
    return ValidationResult::Ok;
}

ValidationResult Validator::validatePasswordMatch(const string& password,
    const string& confirmPassword) {
    if (password != confirmPassword) return ValidationResult::Mismatch;
    return ValidationResult::Ok;
}

bool Validator::isReservedUsername(const string& username) {
    static const char* reserved[] = { "admin", "root", "system", "user", "test" };
    string lower = username;
    for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (const char* name : reserved) {
        if (lower == name) return true;
    }
    return false;
}

bool Validator::containsKeyboardPattern(const std::string& input) {
    if (input.empty()) return false;

    std::string lower = input;
    for (char& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    static const char* patterns[] = {
        "qwertyuiop", "qwerty", "qwert", "werty",
        "asdfghjkl", "asdfgh", "asdf", "sdfg",
        "zxcvbnm", "zxcvbn", "zxcvb", "xcvbn",
        "1234567890", "123456789", "12345678",
        "1234567", "123456", "12345",
        "1qaz2wsx", "qazwsx", "1q2w3e", "1q2w3e4r",
        "q1w2e3", "q1w2e3r4",
        "1qaz", "2wsx", "3edc", "4rfv",
        "zaq1", "xsw2", "cde3", "vfr4",
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
    static const std::regex re(R"((.)\1\1)");
    return std::regex_search(input, re);
}

bool Validator::containsYear(const std::string& input) {
    static const std::regex re(R"((19|20)\d{2})");
    return std::regex_search(input, re);
}

size_t Validator::utf8_length(const std::string& input) {
    size_t count = 0;
    for (unsigned char c : input) {
        if ((c & 0xC0) != 0x80) ++count;
    }
    return count;
}