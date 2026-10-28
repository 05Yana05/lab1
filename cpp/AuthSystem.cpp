#include "AuthSystem.h"
#include "HttpClient.h"
#include "JsonHelper.h"
#include "Validator.h"

#include <iostream>
#include <ctime>
#include <random>
#include <sstream>

using namespace std;

static const string SERVER_URL = "http://localhost:3000";

AuthSystem::AuthSystem(const string& ) {}
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

string AuthSystem::generateNonce() {
    static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    string nonce;
    for (int i = 0; i < 16; ++i) nonce += charset[dist(gen)];
    return nonce;
}

// ----------------------------------------------------------------------------
// Регистрация
// ----------------------------------------------------------------------------
bool AuthSystem::registerUser() {
    string username, password, confirmPassword;

    cout << "\nРЕГИСТРАЦИЯ\n----------------------------\n";
    cout << "Логин (минимум 3 символа): ";
    getline(cin, username);

    ValidationResult userRes = Validator::validateUsername(username);
    if (userRes != ValidationResult::Ok) {
        cout << validationMessage(userRes) << "\n";
        return false;
    }

    cout << "Введите пароль: ";
    getline(cin, password);
    ValidationResult passRes = Validator::validatePassword(password);
    if (passRes != ValidationResult::Ok) {
        cout << validationMessage(passRes) << "\n";
        return false;
    }

    cout << "Подтвердите пароль: ";
    getline(cin, confirmPassword);
    if (password != confirmPassword) {
        cout << "Пароли не совпадают\n";
        return false;
    }

    string json = JsonHelper::buildJson({ {"username", username}, {"password", password} });
    string response = HttpClient::post(SERVER_URL + "/register", json);

    if (response.empty()) { cout << "Ошибка: сервер не отвечает\n"; return false; }

    string status = JsonHelper::extractString(response, "status");
    string message = JsonHelper::extractString(response, "message");
    if (message.empty()) message = "Неизвестная ошибка сервера";

    cout << message << "\n";
    return status == "ok";
}

// ----------------------------------------------------------------------------
// Вход (сохраняем JWT)
// ----------------------------------------------------------------------------
bool AuthSystem::login() {
    string username, password;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        cout << "\nВХОД\n----------------------------\n";
        cout << "Попытка " << (attempt + 1) << " из " << MAX_ATTEMPTS << "\n";

        cout << "Логин: ";
        getline(cin, username);
        if (username.empty()) { cout << "Логин не может быть пустым\n"; continue; }

        cout << "Пароль: ";
        getline(cin, password);
        if (password.empty()) { cout << "Пароль не может быть пустым\n"; continue; }

        time_t timestamp = time(nullptr);
        string nonce = generateNonce();

        stringstream json;
        json << "{"
            << "\"username\":\"" << JsonHelper::escape(username) << "\","
            << "\"password\":\"" << JsonHelper::escape(password) << "\","
            << "\"timestamp\":" << timestamp << ","
            << "\"nonce\":\"" << nonce << "\""
            << "}";

        string response = HttpClient::post(SERVER_URL + "/login", json.str());
        if (response.empty()) { cout << "Ошибка: сервер не отвечает\n"; continue; }

        string status = JsonHelper::extractString(response, "status");
        string message = JsonHelper::extractString(response, "message");
        string code = JsonHelper::extractString(response, "code");

        if (status == "ok") {
            currentToken = JsonHelper::extractString(response, "token");
            cout << "\n" << message << "\n";
            return true;
        }

        cout << message << "\n";
        if (code == "LOCKED" || code == "REPLAY" || code == "STALE_TIMESTAMP") {
            return false;
        }
    }
    cout << "Исчерпаны все попытки входа\n";
    return false;
}

// ----------------------------------------------------------------------------
// Смена пароля (требует токен)
// ----------------------------------------------------------------------------
void AuthSystem::changePassword() {
    if (currentToken.empty()) {
        cout << "Сначала войдите в систему!\n";
        return;
    }

    string oldPassword, newPassword, confirmPassword;

    cout << "\nСМЕНА ПАРОЛЯ\n----------------------------\n";
    cout << "Старый пароль: ";
    getline(cin, oldPassword);

    cout << "Новый пароль: ";
    getline(cin, newPassword);
    ValidationResult passRes = Validator::validatePassword(newPassword);
    if (passRes != ValidationResult::Ok) {
        cout << validationMessage(passRes) << "\n";
        return;
    }

    cout << "Подтвердите новый пароль: ";
    getline(cin, confirmPassword);
    if (newPassword != confirmPassword) {
        cout << "Пароли не совпадают\n";
        return;
    }

    stringstream json;
    json << "{"
        << "\"oldPassword\":\"" << JsonHelper::escape(oldPassword) << "\","
        << "\"newPassword\":\"" << JsonHelper::escape(newPassword) << "\""
        << "}";

    string response = HttpClient::post(SERVER_URL + "/change-password", json.str(), currentToken);
    if (response.empty()) { cout << "Ошибка: сервер не отвечает\n"; return; }

    string status = JsonHelper::extractString(response, "status");
    string message = JsonHelper::extractString(response, "message");
    string code = JsonHelper::extractString(response, "code");

    if (code == "INVALID_TOKEN" || code == "NO_TOKEN") {
        cout << "Сессия истекла. Войдите заново.\n";
        currentToken = "";
    }
    else {
        cout << message << "\n";
    }
}

// ----------------------------------------------------------------------------
// Удаление аккаунта (требует токен)
// ----------------------------------------------------------------------------
void AuthSystem::deleteAccount() {
    if (currentToken.empty()) {
        cout << "Сначала войдите в систему!\n";
        return;
    }

    string password;
    cout << "\nУДАЛЕНИЕ АККАУНТА\n----------------------------\n";
    cout << "Пароль для подтверждения: ";
    getline(cin, password);

    char confirm;
    cout << "Удалить аккаунт? (y/n): ";
    cin >> confirm;
    clearInput();

    if (confirm != 'y' && confirm != 'Y') {
        cout << "Операция отменена\n";
        return;
    }

    stringstream json;
    json << "{\"password\":\"" << JsonHelper::escape(password) << "\"}";

    string response = HttpClient::post(SERVER_URL + "/delete-account", json.str(), currentToken);
    if (response.empty()) { cout << "Ошибка: сервер не отвечает\n"; return; }

    string status = JsonHelper::extractString(response, "status");
    string message = JsonHelper::extractString(response, "message");

    if (status == "ok") {
        currentToken = "";
        cout << message << "\n";
    }
    else {
        cout << message << "\n";
    }
}

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
            currentToken = ""; 
            cout << "До свидания!\n";
            return;
        }
    }
}