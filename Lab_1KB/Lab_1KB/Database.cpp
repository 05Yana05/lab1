#include "Database.h"
#include <iostream>

using namespace std;

Database::Database(const string& dbName) {
    int rc = sqlite3_open(dbName.c_str(), &db);
    if (rc) {
        cout << "Ошибка открытия базы данных: " << sqlite3_errmsg(db) << "\n";
        db = nullptr;
    }
    else {
        cout << "База данных открыта: " << dbName << "\n";
        createTable();
    }
}

Database::~Database() {
    if (db) {
        sqlite3_close(db);
        cout << "База данных закрыта\n";
    }
}

bool Database::executeSQL(const string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, 0, &errMsg);
    if (rc != SQLITE_OK) {
        cout << "Ошибка SQL: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool Database::createTable() {
    string sql = "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "salt TEXT NOT NULL, "
        "password_hash TEXT NOT NULL, "
        "failed_attempts INTEGER DEFAULT 0, "
        "lock_until INTEGER DEFAULT 0"
        ");";

    if (executeSQL(sql)) {
        cout << "Таблица users создана/проверена\n";
        return true;
    }
    return false;
}

User* Database::findUser(const string& username) {
    string sql = "SELECT id, username, salt, password_hash, failed_attempts, lock_until "
        "FROM users WHERE username = '" + username + "';";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return nullptr;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        User* user = new User();
        user->id = sqlite3_column_int(stmt, 0);
        user->username = (const char*)sqlite3_column_text(stmt, 1);
        user->salt = (const char*)sqlite3_column_text(stmt, 2);
        user->passwordHash = (const char*)sqlite3_column_text(stmt, 3);
        user->failedAttempts = sqlite3_column_int(stmt, 4);
        user->lockUntil = sqlite3_column_int64(stmt, 5);
        sqlite3_finalize(stmt);
        return user;
    }

    sqlite3_finalize(stmt);
    return nullptr;
}

bool Database::saveUser(const User& user) {
    string sql;
    if (user.id == 0) {
        sql = "INSERT INTO users (username, salt, password_hash, failed_attempts, lock_until) "
            "VALUES ('" + user.username + "', '" + user.salt + "', '" +
            user.passwordHash + "', " + to_string(user.failedAttempts) + ", " +
            to_string(user.lockUntil) + ");";
    }
    else {
        sql = "UPDATE users SET "
            "salt = '" + user.salt + "', "
            "password_hash = '" + user.passwordHash + "', "
            "failed_attempts = " + to_string(user.failedAttempts) + ", "
            "lock_until = " + to_string(user.lockUntil) + " "
            "WHERE id = " + to_string(user.id) + ";";
    }
    return executeSQL(sql);
}

bool Database::deleteUser(const string& username) {
    string sql = "DELETE FROM users WHERE username = '" + username + "';";
    return executeSQL(sql);
}

bool Database::userExists(const string& username) {
    string sql = "SELECT COUNT(*) FROM users WHERE username = '" + username + "';";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    rc = sqlite3_step(stmt);
    int count = 0;
    if (rc == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);
    return count > 0;
}

void Database::showAllUsers() {
    string sql = "SELECT id, username, failed_attempts, lock_until FROM users;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        cout << "Ошибка запроса\n";
        return;
    }

    cout << "\nСписок пользователей:\n";
    cout << "----------------------------\n";

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
        int id = sqlite3_column_int(stmt, 0);
        const char* username = (const char*)sqlite3_column_text(stmt, 1);
        int attempts = sqlite3_column_int(stmt, 2);
        int lockUntil = sqlite3_column_int(stmt, 3);

        cout << "ID: " << id << "\n";
        cout << "Логин: " << username << "\n";
        cout << "Неудачных попыток: " << attempts << "\n";

        if (lockUntil > 0) {
            char buffer[80];
            time_t lockTime = lockUntil;
            struct tm timeinfo;
            localtime_s(&timeinfo, &lockTime);
            strftime(buffer, sizeof(buffer), "%H:%M:%S %d.%m.%Y", &timeinfo);  // ← &timeinfo
            cout << "Заблокирован до: " << buffer << "\n";
        }
        else {
            cout << "Заблокирован до: нет\n";
        }
        cout << "----------------------------\n";
    }

    if (count == 0) cout << "Нет зарегистрированных пользователей\n";
    sqlite3_finalize(stmt);
}

bool Database::isOpen() const {
    return db != nullptr;
}