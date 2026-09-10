#include "Validator.h"
#include <iostream>
#include <cctype>

using namespace std;

bool Validator::validateUsername(const string& username) {
    if (username.empty()) {
        cout << "Логин не может быть пустым\n";
        return false;
    }
    if (username.length() < 3) {
        cout << "Логин должен содержать минимум 3 символа\n";
        return false;
    }
    if (username.length() > 20) {
        cout << "Логин должен содержать максимум 20 символов\n";
        return false;
    }
    if (username.find(' ') != string::npos) {
        cout << "Логин не должен содержать пробелы\n";
        return false;
    }
    if (username.find(',') != string::npos) {
        cout << "Логин не должен содержать запятую\n";
        return false;
    }
    for (char c : username) {
        if (!isalnum(c) && c != '_') {
            cout << "Логин должен содержать только буквы, цифры и '_'\n";
            return false;
        }
    }
    return true;
}

bool Validator::validatePassword(const string& password) {
    if (password.empty()) {
        cout << "Пароль не может быть пустым\n";
        return false;
    }
    if (password.length() < 8) {
        cout << "Пароль должен содержать минимум 8 символов\n";
        return false;
    }
    if (password.length() > 50) {
        cout << "Пароль должен содержать максимум 50 символов\n";
        return false;
    }
    if (password.find(' ') != string::npos) {
        cout << "Пароль не должен содержать пробелы\n";
        return false;
    }
    if (password.find(',') != string::npos) {
        cout << "Пароль не должен содержать запятую\n";
        return false;
    }

    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        if (c >= 'A' && c <= 'Z') hasUpper = true;
        else if (c >= 'a' && c <= 'z') hasLower = true;
        else if (c >= '0' && c <= '9') hasDigit = true;
        else hasSpecial = true;
    }

    if (!hasUpper) {
        cout << "Пароль должен содержать заглавную букву\n";
        return false;
    }
    if (!hasLower) {
        cout << "Пароль должен содержать строчную букву\n";
        return false;
    }
    if (!hasDigit) {
        cout << "Пароль должен содержать цифру\n";
        return false;
    }
    if (!hasSpecial) {
        cout << "Пароль должен содержать специальный символ\n";
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