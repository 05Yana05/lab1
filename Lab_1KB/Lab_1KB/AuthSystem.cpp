#include "AuthSystem.h"
#include "User.h"
#include "Hash.h"
#include <iostream>
#include <ctime>
#include <random>
#include <cmath>
#include <fstream>

using namespace std;

AuthSystem::AuthSystem(const string& dbName) : db(dbName) {}

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

void AuthSystem::logEvent(const std::string& event) {
    // Открываем файл в режиме добавления (app)
    std::ofstream log("auth.log", std::ios::app);
    if (!log.is_open()) return;

    // Получаем текущее время в читаемом виде
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);

    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);

    // Пишем строку
    log << "[" << buffer << "] " << event << "\n";
}

string AuthSystem::generateNonce() {
    static const char charset[] =
        "0123456789abcdefghijklmnopqrstuvwxyz";
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    string nonce;
    for (int i = 0; i < 16; ++i) {
        nonce += charset[dist(gen)];
    }
    return nonce;
}

bool AuthSystem::checkFreshness(time_t timestamp) {
    time_t now = time(nullptr);
    return std::abs((long long)(now - timestamp)) <= TIMESTAMP_WINDOW;
}

bool AuthSystem::checkAndMarkNonce(const string& nonce) {
    if (usedNonces.count(nonce)) {
        return false;
    }
    usedNonces.insert(nonce);
    return true;
}

bool AuthSystem::registerUser() {
    string username, password, confirmPassword;

    cout << "\nРЕГИСТРАЦИЯ\n";
    cout << "----------------------------\n";

    cout << "Логин (минимум 3 символа): ";
    cin >> username;

    if (!Validator::validateUsername(username)) return false;
    if (Validator::isReservedUsername(username)) return false;
    if (db.userExists(username)) {
        cout << "Пользователь уже существует\n";
        return false;
    }

    cout << "\nВведите пароль (без ограничений):\n";

    cout << "Введите пароль: ";
    cin >> password;
    if (!Validator::validatePassword(password)) return false;
    if (db.isCommonPassword(password)) {
        cout << "Этот пароль слишком распространён. Придумайте другой.\n";
        return false;
    }

    cout << "Подтвердите пароль: ";
    cin >> confirmPassword;
    if (!Validator::validatePasswordMatch(password, confirmPassword)) return false;

    User newUser(username, password);
    db.saveUser(newUser);

    logEvent("REGISTER OK: username=" + username);
    cout << "\nРегистрация успешна!\n";
    return true;
}


bool AuthSystem::login() {
    string username, password;
    User* user = nullptr;

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

        // Имитация: клиент формирует пакет с timestamp и nonce
        time_t clientTimestamp = time(nullptr);
        string clientNonce = generateNonce();

        // Имитация: сервер принимает пакет и проверяет его
        cout << "[СЕРВЕР] Получен пакет: username=" << username
            << ", timestamp=" << clientTimestamp
            << ", nonce=" << clientNonce << "\n";

        if (!checkFreshness(clientTimestamp)) {
            logEvent("REPLAY DETECTED: username=" + username +
                ", reason=stale timestamp");
            cout << "[СЕРВЕР] Отказ: временная метка слишком старая\n";
            continue;
        }
        if (!checkAndMarkNonce(clientNonce)) {
            logEvent("REPLAY DETECTED: username=" + username +
                ", reason=nonce reused, nonce=" + clientNonce);
            cout << "[СЕРВЕР] Отказ: replay detected (nonce уже использовался)\n";
            continue;
        }

        user = db.findUser(username);
        if (!user) {
            cout << "Пользователь не найден\n";
            continue;
        }

        if (user->isLocked()) {
            int remaining = user->getRemainingLockTime();
            cout << "Аккаунт заблокирован на " << remaining << " секунд\n";
            delete user;
            return false;
        }

        cout << "Пароль: ";
        cin >> password;

        if (password.empty()) {
            cout << "Пароль не может быть пустым\n";
            user->failedAttempts++;
            db.saveUser(*user);
            delete user;
            continue;
        }

        if (Hash::verifyPassword(password, user->passwordHash)) {
            user->failedAttempts = 0;
            db.saveUser(*user);
            logEvent("LOGIN OK: username=" + username);
            cout << "\nДобро пожаловать, " << username << "!\n";
            delete user;
            return true;
        }
        else {
            user->failedAttempts++;
            logEvent("LOGIN FAIL: username=" + username +
                ", reason=wrong password, attempt=" +
                std::to_string(user->failedAttempts));
            cout << "Неверный пароль\n";

            if (user->failedAttempts >= MAX_ATTEMPTS) {
                user->lockUntil = time(nullptr) + LOCK_DURATION;
                db.saveUser(*user);
                logEvent("ACCOUNT LOCKED: username=" + username +
                    ", duration=" + std::to_string(LOCK_DURATION) + "s");
                cout << "Превышено количество попыток!\n";
                cout << "Аккаунт заблокирован на " << LOCK_DURATION << " секунд\n";
                delete user;
                return false;
            }

            db.saveUser(*user);
            cout << "Осталось попыток: " << (MAX_ATTEMPTS - user->failedAttempts) << "\n";
        }

        delete user;
    }

    return false;
}

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

    User* user = db.findUser(username);
    if (!user) {
        cout << "Пользователь не найден\n";
        return;
    }

    if (user->isLocked()) {
        cout << "Аккаунт заблокирован\n";
        delete user;
        return;
    }

    cout << "Старый пароль: ";
    cin >> oldPassword;

    if (oldPassword.empty()) {
        cout << "Пароль не может быть пустым\n";
        delete user;
        return;
    }

    if (!Hash::verifyPassword(oldPassword, user->passwordHash)) {
        cout << "Неверный старый пароль\n";
        delete user;
        return;
    }

    cout << "\nНовый пароль: ";
    cin >> newPassword;

    if (!Validator::validatePassword(newPassword)) {
        delete user;
        return;
    }
    if (db.isCommonPassword(newPassword)) {
        cout << "Этот пароль слишком распространён. Выберите другой.\n";
        delete user;
        return;
    }

    cout << "Подтвердите новый пароль: ";
    cin >> confirmPassword;

    if (!Validator::validatePasswordMatch(newPassword, confirmPassword)) {
        delete user;
        return;
    }

    user->passwordHash = Hash::hashPassword(newPassword);
    user->failedAttempts = 0;
    db.saveUser(*user);

    logEvent("PASSWORD CHANGED: username=" + username);
    cout << "Пароль успешно изменен\n";
    delete user;
}

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

    User* user = db.findUser(username);
    if (!user) {
        cout << "Пользователь не найден\n";
        return;
    }

    cout << "Пароль для подтверждения: ";
    cin >> password;

    if (password.empty()) {
        cout << "Пароль не может быть пустым\n";
        delete user;
        return;
    }

    if (!Hash::verifyPassword(password, user->passwordHash)) {
        cout << "Неверный пароль\n";
        delete user;
        return;
    }

    char confirm;
    cout << "Удалить аккаунт " << username << "? (y/n): ";
    cin >> confirm;

    while (confirm != 'y' && confirm != 'Y' && confirm != 'n' && confirm != 'N') {
        cout << "Введите 'y' для подтверждения или 'n' для отмены: ";
        cin >> confirm;
    }

    if (confirm == 'y' || confirm == 'Y') {
        db.deleteUser(username);
        logEvent("ACCOUNT DELETED: username=" + username);
        cout << "Аккаунт удален\n";
    }
    else {
        cout << "Операция отменена\n";
    }

    delete user;
}

void AuthSystem::showAllUsers() {
    db.showAllUsers();
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