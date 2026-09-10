#pragma once
#include <string>

class Validator {
public:
    static bool validateUsername(const std::string& username);
    static bool validatePassword(const std::string& password);
    static bool validatePasswordMatch(const std::string& password, const std::string& confirmPassword);
    static bool isReservedUsername(const std::string& username);
};