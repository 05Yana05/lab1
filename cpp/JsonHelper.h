#pragma once
#include <string>

// Минимальный парсер JSON для наших простых ответов сервера.
// Работает только со строками вида {"status":"ok","message":"..."}.
class JsonHelper {
public:
    // Извлекает значение строкового поля по ключу.
    // Пример: extractString("{\"status\":\"ok\"}", "status") вернёт "ok"
    // Возвращает пустую строку, если ключ не найден.
    static std::string extractString(const std::string& json, const std::string& key);

    // Экранирует строку для вставки в JSON-значение.
    // Удваивает кавычки, экранирует обратный слеш.
    static std::string escape(const std::string& value);

    // Формирует JSON-объект из пар ключ-значение.
    // Пример: buildJson({{"username","alice"},{"password","123"}})
    //         → {"username":"alice","password":"123"}
    static std::string buildJson(const std::initializer_list<std::pair<std::string, std::string>>& pairs);
};