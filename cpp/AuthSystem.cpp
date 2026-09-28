#include "AuthSystem.h"
#include "HttpClient.h"
#include "JsonHelper.h"
#include "Validator.h"

#include <iostream>
#include <ctime>
#include <random>
#include <sstream>

using namespace std;

// Адрес сервера
static const string SERVER_URL = "http://localhost:3000";

AuthSystem::AuthSystem(const string& /*dbName*/) {
    // Конструктор больше не открывает БД — она на сервере
}

AuthSystem::~AuthSystem() {}

void AuthSystem::clearInput() {
    cin.clear();
    cin.ignore(10000, '\n');
}

int AuthSystem::getValidatedChoice(int min, int max) {
    int choice;
    while (true) {
        cin >> choice;
        if (cin.fail()) {
            clearInput();
            cout << "Введите число\n";
            cout << "Выберите действие (" << min << "-" << max << "): ";
        }
        else if (choice < min || choice > max) {
            cout << "Введите число от " << min << " до " << max << "\n";
            cout << "Выберите действие: ";
        }
        else {
            clearInput();
            return choice;
        }
    }
}

// Генерация случайного nonce (16 символов)
string AuthSystem::generateNonce() {
    static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    string nonce;
    for (int i = 0; i < 16; ++i) {
        nonce += charset[dist(gen)];
    }
    return nonce;
}

// Регистрация через сервер
bool AuthSystem::registerUser() {
    string username, password, confirmPassword;

    cout << "\nРЕГИСТРАЦИЯ\n";
    cout << "----------------------------\n";

    cout << "Логин (минимум 3 символа): ";
    cin >> username;

    if (!Validator::validateUsername(username)) return false;
    if (Validator::isReservedUsername(username)) return false;

    cout << "\nВведите пароль (без ограничений):\n";
    cout << "Введите пароль: ";
    cin >> password;

    if (!Validator::validatePassword(password)) return false;

    cout << "Подтвердите пароль: ";
    cin >> confirmPassword;

    if (!Validator::validatePasswordMatch(password, confirmPassword)) return false;

    // Формируем JSON и отправляем POST /register
    string json = JsonHelper::buildJson({
        {"username", username},
        {"password", password}
        });

    string response = HttpClient::post(SERVER_URL + "/register", json);
    if (response.empty()) {
        cout << "Ошибка: сервер не отвечает\n";
        return false;
    }

    string status = JsonHelper::extractString(response, "status");
    string message = JsonHelper::extractString(response, "message");

    if (status == "ok") {
        cout << "\nРегистрация успешна!\n";
        return true;
    }
    else {
        cout << message << "\n";
        return false;
    }
}

// Вход через сервер
bool AuthSystem::login() {
    string username, password;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        cout << "\nВХОД\n";
        cout << "----------------------------\n";
        cout << "Попытка " << (attempt + 1) << " из " << MAX_ATTEMPTS << "\n";

        cout << "Логин: ";
        cin >> username;
        if (username.empty()) {
            cout << "Логин не может быть пустым\n";
            continue;
        }

        cout << "Пароль: ";
        cin >> password;
        if (password.empty()) {
            cout << "Пароль не может быть пустым\n";
            continue;
        }

        // Формируем пакет: username, password, timestamp, nonce
        time_t timestamp = time(nullptr);
        string nonce = generateNonce();

        cout << "[КЛИЕНТ] Отправка запроса: timestamp=" << timestamp
            << ", nonce=" << nonce << "\n";

        // timestamp — число, поэтому JSON собираем вручную
        stringstream json;
        json << "{"
            << "\"username\":\"" << JsonHelper::escape(username) << "\","
            << "\"password\":\"" << JsonHelper::escape(password) << "\","
            << "\"timestamp\":" << timestamp << ","
            << "\"nonce\":\"" << nonce << "\""
            << "}";

        string response = HttpClient::post(SERVER_URL + "/login", json.str());
        if (response.empty()) {
            cout << "Ошибка: сервер не отвечает\n";
            continue;
        }

        string status = JsonHelper::extractString(response, "status");
        string message = JsonHelper::extractString(response, "message");

        if (status == "ok") {
            cout << "\nДобро пожаловать, " << username << "!\n";
            return true;
        }
        else {
            cout << message << "\n";
            // Если сообщение про блокировку — выходим
            if (message.find("locked") != string::npos) {
                return false;
            }
            // Иначе продолжаем попытки
        }
    }

    return false;
}

// Смена пароля через сервер
void AuthSystem::changePassword() {
    string username, oldPassword, newPassword, confirmPassword;

    cout << "\nСМЕНА ПАРОЛЯ\n";
    cout << "----------------------------\n";

    cout << "Логин: ";
    cin >> username;
    if (username.empty()) {
        cout << "Логин не может быть пустым\n";
        return;
    }

    cout << "Старый пароль: ";
    cin >> oldPassword;
    if (oldPassword.empty()) {
        cout << "Пароль не может быть пустым\n";
        return;
    }

    cout << "\nНовый пароль: ";
    cin >> newPassword;
    if (!Validator::validatePassword(newPassword)) return;

    cout << "Подтвердите новый пароль: ";
    cin >> confirmPassword;
    if (!Validator::validatePasswordMatch(newPassword, confirmPassword)) return;

    time_t timestamp = time(nullptr);
    string nonce = generateNonce();

    stringstream json;
    json << "{"
        << "\"username\":\"" << JsonHelper::escape(username) << "\","
        << "\"oldPassword\":\"" << JsonHelper::escape(oldPassword) << "\","
        << "\"newPassword\":\"" << JsonHelper::escape(newPassword) << "\","
        << "\"timestamp\":" << timestamp << ","
        << "\"nonce\":\"" << nonce << "\""
        << "}";

    string response = HttpClient::post(SERVER_URL + "/change-password", json.str());
    if (response.empty()) {
        cout << "Ошибка: сервер не отвечает\n";
        return;
    }

    string status = JsonHelper::extractString(response, "status");
    string message = JsonHelper::extractString(response, "message");

    cout << message << "\n";
}

// Удаление аккаунта через сервер
void AuthSystem::deleteAccount() {
    string username, password;

    cout << "\nУДАЛЕНИЕ АККАУНТА\n";
    cout << "----------------------------\n";

    cout << "Логин: ";
    cin >> username;
    if (username.empty()) {
        cout << "Логин не может быть пустым\n";
        return;
    }

    cout << "Пароль для подтверждения: ";
    cin >> password;
    if (password.empty()) {
        cout << "Пароль не может быть пустым\n";
        return;
    }

    char confirm;
    cout << "Удалить аккаунт " << username << "? (y/n): ";
    cin >> confirm;
    while (confirm != 'y' && confirm != 'Y' && confirm != 'n' && confirm != 'N') {
        cout << "Введите 'y' для подтверждения или 'n' для отмены: ";
        cin >> confirm;
    }

    if (confirm != 'y' && confirm != 'Y') {
        cout << "Операция отменена\n";
        return;
    }

    time_t timestamp = time(nullptr);
    string nonce = generateNonce();

    stringstream json;
    json << "{"
        << "\"username\":\"" << JsonHelper::escape(username) << "\","
        << "\"password\":\"" << JsonHelper::escape(password) << "\","
        << "\"timestamp\":" << timestamp << ","
        << "\"nonce\":\"" << nonce << "\""
        << "}";

    string response = HttpClient::post(SERVER_URL + "/delete-account", json.str());
    if (response.empty()) {
        cout << "Ошибка: сервер не отвечает\n";
        return;
    }

    string status = JsonHelper::extractString(response, "status");
    string message = JsonHelper::extractString(response, "message");

    if (status == "ok") {
        cout << message << "\n";
    }
    else {
        cout << message << "\n";
    }
}

// Показать всех пользователей (запрос GET /users)
void AuthSystem::showAllUsers() {
    string response = HttpClient::get(SERVER_URL + "/users");
    if (response.empty()) {
        cout << "Ошибка: сервер не отвечает\n";
        return;
    }

    cout << "\nСырой ответ сервера:\n" << response << "\n";
}

void AuthSystem::showMenu() {
    while (true) {
        cout << "\nСИСТЕМА АУТЕНТИФИКАЦИИ\n";
        cout << "1. Вход в систему\n";
        cout << "2. Регистрация\n";
        cout << "3. Сменить пароль\n";
        cout << "4. Удалить аккаунт\n";
        cout << "5. Показать всех пользователей\n";
        cout << "6. Выход\n";
        cout << "Выберите действие (1-6): ";

        int choice = getValidatedChoice(1, 6);

        switch (choice) {
        case 1: login(); break;
        case 2: registerUser(); break;
        case 3: changePassword(); break;
        case 4: deleteAccount(); break;
        case 5: showAllUsers(); break;
        case 6:
            cout << "До свидания!\n";
            return;
        }
    }
}