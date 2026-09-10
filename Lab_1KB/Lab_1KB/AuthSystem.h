#pragma once
#include "Database.h"
#include "Validator.h"

class AuthSystem {
private:
    Database db;
    const int MAX_ATTEMPTS = 3;
    const int LOCK_DURATION = 30;

    void clearInput();
    int getValidatedChoice(int min, int max);

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