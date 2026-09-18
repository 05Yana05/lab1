#pragma once
#include "Database.h"
#include "Validator.h"
#include <string>
#include <set>
#include <ctime>

class AuthSystem {
private:
    Database db;
    const int MAX_ATTEMPTS = 3;
    const int LOCK_DURATION = 30;
    const int TIMESTAMP_WINDOW = 30;

    std::set<std::string> usedNonces;

    void clearInput();
    int getValidatedChoice(int min, int max);
    void logEvent(const std::string& event);

    std::string generateNonce();
    bool checkFreshness(time_t timestamp);
    bool checkAndMarkNonce(const std::string& nonce);

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