#include "HttpClient.h"

#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "winhttp.lib")

using namespace std;

// Разбирает URL вида "http://localhost:3000/login"
// на хост ("localhost"), порт (3000) и путь ("/login")
static bool parseUrl(const string& url, wstring& host, INTERNET_PORT& port, wstring& path) {
    // Убираем "http://" или "https://"
    string rest = url;
    if (rest.rfind("http://", 0) == 0) {
        rest = rest.substr(7);
        port = 80;
    }
    else if (rest.rfind("https://", 0) == 0) {
        rest = rest.substr(8);
        port = 443;
    }
    else {
        return false;
    }

    // Отделяем хост от пути
    size_t slashPos = rest.find('/');
    string hostAndPort = (slashPos == string::npos) ? rest : rest.substr(0, slashPos);
    string pathStr = (slashPos == string::npos) ? "/" : rest.substr(slashPos);

    // Отделяем порт от хоста (если есть)
    size_t colonPos = hostAndPort.find(':');
    string hostStr = (colonPos == string::npos) ? hostAndPort : hostAndPort.substr(0, colonPos);
    if (colonPos != string::npos) {
        port = (INTERNET_PORT)stoi(hostAndPort.substr(colonPos + 1));
    }

    // Конвертируем в wstring (WinHTTP работает с широкими строками)
    host.assign(hostStr.begin(), hostStr.end());
    path.assign(pathStr.begin(), pathStr.end());
    return true;
}

// Общая функция для HTTP-запросов (GET или POST)
static string sendRequest(const string& url, const string& body, const wstring& method) {
    wstring host, path;
    INTERNET_PORT port = 80;

    if (!parseUrl(url, host, port, path)) {
        cerr << "[HttpClient] Неверный URL: " << url << "\n";
        return "";
    }

    // Открываем сессию WinHTTP
    HINTERNET hSession = WinHttpOpen(
        L"CppAuthClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        cerr << "[HttpClient] WinHttpOpen failed\n";
        return "";
    }

    // Подключаемся к серверу
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        cerr << "[HttpClient] WinHttpConnect failed\n";
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Открываем запрос
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        method.c_str(),         // L"GET" или L"POST"
        path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);                     // 0 = HTTP, WINHTTP_FLAG_SECURE = HTTPS
    if (!hRequest) {
        cerr << "[HttpClient] WinHttpOpenRequest failed\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Формируем заголовки
    wstring headers;
    LPVOID bodyPtr = WINHTTP_NO_REQUEST_DATA;
    DWORD bodyLen = 0;

    if (method == L"POST") {
        headers = L"Content-Type: application/json\r\n";
        bodyPtr = (LPVOID)body.c_str();
        bodyLen = (DWORD)body.size();
    }

    // Отправляем запрос
    BOOL ok = WinHttpSendRequest(
        hRequest,
        headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
        headers.empty() ? 0 : (DWORD)-1L,
        bodyPtr,
        bodyLen,
        bodyLen,
        0);

    if (!ok) {
        cerr << "[HttpClient] WinHttpSendRequest failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Принимаем ответ
    ok = WinHttpReceiveResponse(hRequest, NULL);
    if (!ok) {
        cerr << "[HttpClient] WinHttpReceiveResponse failed\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Читаем тело ответа по частям
    string response;
    DWORD bytesAvailable = 0;
    do {
        bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) break;
        if (bytesAvailable == 0) break;

        vector<char> buffer(bytesAvailable + 1, 0);
        DWORD bytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) break;
        response.append(buffer.data(), bytesRead);
    } while (bytesAvailable > 0);

    // Освобождаем ресурсы
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

string HttpClient::post(const string& url, const string& jsonBody) {
    return sendRequest(url, jsonBody, L"POST");
}

string HttpClient::get(const string& url) {
    return sendRequest(url, "", L"GET");
}