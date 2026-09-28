#pragma once
#include <string>

class AuthSystem {
private:
    const int MAX_ATTEMPTS = 3;

    void clearInput();
    int getValidatedChoice(int min, int max);
    std::string generateNonce();

public:
    AuthSystem(const std::string& dbName = "users.db");
    ~AuthSystem();

    bool registerUser();
    bool login();
    void changePassword();
    void deleteAccount();
    void showAllUsers();
    void showMenu();
};