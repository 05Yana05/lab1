#pragma once
#include <string>

class Hash {
public:
    // Хеширует пароль через Argon2
    // Возвращает PHC-строку, которая уже содержит соль и параметры.
    static std::string hashPassword(const std::string& password);

    // Проверяет пароль против сохранённой PHC-строки.
    static bool verifyPassword(const std::string& password, const std::string& stored);
};