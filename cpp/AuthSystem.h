#pragma once
#include <string>

class AuthSystem {
private:
    const int MAX_ATTEMPTS = 3;

    // ПОЛЯ ДЛЯ СЕССИЙ
    std::string accessToken;
    std::string refreshToken;
    // const std::string AES_KEY = "my_super_secret_aes_key_12345"; // <-- Эту строку можно удалить

    void clearInput();
    int getValidatedChoice(int min, int max);
    std::string generateNonce();

    // УМНЫЙ ЗАПРОС С АВТООБНОВЛЕНИЕМ
    std::string postWithAuth(const std::string& path, const std::string& jsonBody);

public:
    AuthSystem(const std::string& dbName = "users.db");
    ~AuthSystem();

    void saveTokensToDisk();
    void loadTokensFromDisk();
    bool registerUser();
    bool login();
    void changePassword();
    void deleteAccount();
    void showAllUsers();
    void showMenu();
};