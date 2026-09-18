#pragma once
#include <string>

class Validator {
public:
    static bool validateUsername(const std::string& username);
    static bool validatePassword(const std::string& password);
    static bool validatePasswordMatch(const std::string& password, const std::string& confirmPassword);
    static bool isReservedUsername(const std::string& username);
    static bool containsKeyboardPattern(const std::string& input);
    static bool hasRepeatedChars(const std::string& input);
    static bool containsYear(const std::string& input);
    static size_t utf8_length(const std::string& input);   // ← новый
};