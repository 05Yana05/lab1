#pragma once
#include <string>

// Результат валидации. Ок = Ok, иначе — конкретная причина.
enum class ValidationResult {
    Ok,
    Empty,
    TooShort,
    KeyboardPattern,
    RepeatedChars,
    ContainsYear,
    Reserved,
    Mismatch
};

// Преобразовать результат в русское сообщение
std::string validationMessage(ValidationResult result);

class Validator {
public:
    static ValidationResult validateUsername(const std::string& username);
    static ValidationResult validatePassword(const std::string& password);
    static ValidationResult validatePasswordMatch(const std::string& password,
        const std::string& confirmPassword);

    static bool containsKeyboardPattern(const std::string& input);
    static bool hasRepeatedChars(const std::string& input);
    static bool containsYear(const std::string& input);
    static size_t utf8_length(const std::string& input);

private:
    static bool isReservedUsername(const std::string& username);
};