#include "AuthSystem.h"
#include "HttpClient.h"
#include "JsonHelper.h"
#include "Validator.h"
#include "CryptoHelper.h" 
#include <iostream>
#include <ctime>
#include <random>
#include <sstream>
#include <fstream> 

using namespace std;
static const string SERVER_URL = "http://localhost:3000";
static const string AES_KEY = "my_super_secret_aes_key_12345";

// Конструктор: при запуске программы сразу пытаемся загрузить токены с диска
AuthSystem::AuthSystem(const string&) {
    loadTokensFromDisk();
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
        if (cin.fail()) { clearInput(); cout << "Введите число\nВыберите действие (" << min << "-" << max << "): "; }
        else if (choice < min || choice > max) { cout << "Введите число от " << min << " до " << max << "\nВыберите действие: "; }
        else { clearInput(); return choice; }
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

// --- СОХРАНЕНИЕ И ЗАГРУЗКА ТОКЕНОВ ---
void AuthSystem::saveTokensToDisk() {
    if (accessToken.empty() || refreshToken.empty()) return;

    string data = accessToken + "|" + refreshToken;
    try {
        string encrypted = CryptoHelper::encrypt(data, AES_KEY);
        ofstream file("tokens.dat");
        if (file.is_open()) {
            file << encrypted;
            file.close();
        }
    }
    catch (...) {
        // Если не удалось зашифровать - пропускаем
    }
}

void AuthSystem::loadTokensFromDisk() {
    ifstream file("tokens.dat");
    if (!file.is_open()) return;

    string encrypted;
    getline(file, encrypted);
    file.close();

    if (encrypted.empty()) return;

    try {
        string decrypted = CryptoHelper::decrypt(encrypted, AES_KEY);
        size_t pos = decrypted.find('|');
        if (pos != string::npos) {
            accessToken = decrypted.substr(0, pos);
            refreshToken = decrypted.substr(pos + 1);
        }
    }
    catch (...) {
        // Если файл поврежден (или ключ другой), ничего не загружаем
    }
}

string AuthSystem::postWithAuth(const string& path, const string& jsonBody) {
    string nonce = generateNonce();
    time_t timestamp = time(nullptr);

    string fullBody = "{\"nonce\":\"" + nonce + "\",\"timestamp\":" + to_string(timestamp) + "," + jsonBody.substr(1);
    string response = HttpClient::post(SERVER_URL + path, fullBody, accessToken);

    // Если токен протух, обновляем
    if (response.find("401") != string::npos || response.find("Токен истек") != string::npos) {
        cout << "\n[СЕССИЯ] Обновление токена...\n";

        string refreshBody = "{\"refreshToken\":\"" + refreshToken + "\"}";
        string refreshRes = HttpClient::post(SERVER_URL + "/refresh", refreshBody);

        if (refreshRes.find("403") == string::npos && !refreshRes.empty()) {
            accessToken = JsonHelper::extractString(refreshRes, "accessToken");
            refreshToken = JsonHelper::extractString(refreshRes, "refreshToken");
            saveTokensToDisk(); // <-- СОХРАНЯЕМ НОВЫЕ ТОКЕНЫ
            cout << "[СЕССИЯ] Токен обновлен!\n";

            // Повторяем запрос
            return HttpClient::post(SERVER_URL + path, fullBody, accessToken);
        }
        else {
            cout << "[СЕССИЯ] Сессия истекла. Войдите заново.\n";
            accessToken = ""; refreshToken = "";
            remove("tokens.dat"); // Удаляем битый файл
            return "";
        }
    }
    return response;
}

bool AuthSystem::registerUser() {
    string username, password, confirmPassword;
    cout << "\nРЕГИСТРАЦИЯ\n----------------------------\nЛогин: ";
    getline(cin, username);
    if (Validator::validateUsername(username) != ValidationResult::Ok) { cout << validationMessage(Validator::validateUsername(username)) << "\n"; return false; }

    cout << "Пароль: "; getline(cin, password);
    if (Validator::validatePassword(password) != ValidationResult::Ok) { cout << validationMessage(Validator::validatePassword(password)) << "\n"; return false; }

    cout << "Подтвердите пароль: "; getline(cin, confirmPassword);
    if (password != confirmPassword) { cout << "Пароли не совпадают\n"; return false; }

    string json = JsonHelper::buildJson({ {"username", username}, {"password", password} });
    string response = HttpClient::post(SERVER_URL + "/register", json);
    if (response.empty()) { cout << "Ошибка сети\n"; return false; }

    cout << JsonHelper::extractString(response, "message") << "\n";
    return JsonHelper::extractString(response, "status") == "ok";
}

bool AuthSystem::login() {
    string username, password;
    cout << "\nВХОД\n----------------------------\nЛогин: "; getline(cin, username);
    cout << "Пароль: "; getline(cin, password);

    string nonce = generateNonce();
    time_t timestamp = time(nullptr);

    string json = "{\"username\":\"" + JsonHelper::escape(username) + "\",\"password\":\"" + JsonHelper::escape(password) + "\",\"nonce\":\"" + nonce + "\",\"timestamp\":" + to_string(timestamp) + "}";
    string response = HttpClient::post(SERVER_URL + "/login", json);

    if (response.empty()) { cout << "Ошибка сети\n"; return false; }

    string status = JsonHelper::extractString(response, "status");
    if (status == "ok") {
        accessToken = JsonHelper::extractString(response, "accessToken");
        refreshToken = JsonHelper::extractString(response, "refreshToken");
        saveTokensToDisk(); // <-- СОХРАНЯЕМ ТОКЕНЫ ПОСЛЕ ВХОДА
        cout << "\nДобро пожаловать, " << username << "!\n";
        return true;
    }
    else {
        cout << "Неверные данные\n";
        return false;
    }
}

void AuthSystem::changePassword() {
    // Если токенов нет, пробуем загрузить их с диска (вдруг пользователь перезапустил программу)
    if (accessToken.empty()) {
        loadTokensFromDisk();
        if (accessToken.empty()) {
            cout << "Сначала войдите!\n";
            return;
        }
    }

    string oldP, newP, confP;
    cout << "\nСМЕНА ПАРОЛЯ\n----------------------------\nСтарый пароль: "; getline(cin, oldP);
    cout << "Новый пароль: "; getline(cin, newP);
    cout << "Подтвердите: "; getline(cin, confP);

    if (newP != confP) { cout << "Не совпадают\n"; return; }

    string json = "{\"oldPassword\":\"" + JsonHelper::escape(oldP) + "\",\"newPassword\":\"" + JsonHelper::escape(newP) + "\"}";
    string response = postWithAuth("/change-password", json);

    if (!response.empty()) cout << JsonHelper::extractString(response, "message") << "\n";
}

void AuthSystem::deleteAccount() {
    if (accessToken.empty()) {
        loadTokensFromDisk();
        if (accessToken.empty()) { cout << "Сначала войдите!\n"; return; }
    }

    string password;
    cout << "\nУДАЛЕНИЕ\n----------------------------\nПароль: "; getline(cin, password);

    char confirm;
    cout << "Удалить аккаунт? (y/n): "; cin >> confirm; clearInput();
    if (confirm != 'y' && confirm != 'Y') { cout << "Отменено\n"; return; }

    string json = "{\"password\":\"" + JsonHelper::escape(password) + "\"}";
    string response = postWithAuth("/delete-account", json);

    if (!response.empty()) {
        cout << JsonHelper::extractString(response, "message") << "\n";
        accessToken = ""; refreshToken = "";
        remove("tokens.dat"); // Удаляем файл после удаления аккаунта
    }
}

void AuthSystem::showAllUsers() {
    string response = HttpClient::get(SERVER_URL + "/users");
    if (!response.empty()) cout << "\nСырой ответ:\n" << response << "\n";
}

void AuthSystem::showMenu() {
    while (true) {
        cout << "\nСИСТЕМА АУТЕНТИФИКАЦИИ\n1. Вход\n2. Регистрация\n3. Сменить пароль\n4. Удалить аккаунт\n5. Список\n6. Выход\nВыберите действие (1-6): ";
        int choice = getValidatedChoice(1, 6);
        switch (choice) {
        case 1: login(); break;
        case 2: registerUser(); break;
        case 3: changePassword(); break;
        case 4: deleteAccount(); break;
        case 5: showAllUsers(); break;
        case 6:
            if (!accessToken.empty()) {
                HttpClient::post(SERVER_URL + "/logout", "", accessToken);
                accessToken = ""; refreshToken = "";
                remove("tokens.dat"); // УДАЛЯЕМ ФАЙЛ ПРИ ВЫХОДЕ
            }
            cout << "До свидания!\n"; return;
        }
    }
}