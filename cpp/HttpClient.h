#pragma once
#include <string>

// Обёртка над WinHTTP для отправки POST-запросов с JSON-телом.
class HttpClient {
public:
    // Отправляет POST-запрос на url с JSON-телом и токеном
    static std::string post(const std::string& url, const std::string& jsonBody, const std::string& token = "");

    // Отправляет GET-запрос на url
    static std::string get(const std::string& url);
};