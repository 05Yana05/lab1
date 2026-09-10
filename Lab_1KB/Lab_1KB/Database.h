#pragma once
#include <string>
#include "User.h"
#include "sqlite3.h"

class Database {
private:
    sqlite3* db;
    bool executeSQL(const std::string& sql);

public:
    Database(const std::string& dbName = "users.db");
    ~Database();

    bool createTable();
    User* findUser(const std::string& username);
    bool saveUser(const User& user);
    bool deleteUser(const std::string& username);
    bool userExists(const std::string& username);
    void showAllUsers();
    bool isOpen() const;
};