#pragma once
#include <string>

// Обёртка над WinHTTP для отправки POST-запросов с JSON-телом.
// Пример: HttpClient::post("http://localhost:3000/login", jsonBody)
class HttpClient {
public:
    // Отправляет POST-запрос на url с JSON-телом.
    // Возвращает тело ответа от сервера (строку JSON).
    // В случае ошибки возвращает пустую строку.
    static std::string post(const std::string& url, const std::string& jsonBody);

    // Отправляет GET-запрос на url.
    // Возвращает тело ответа от сервера (строку JSON).
    static std::string get(const std::string& url);
};