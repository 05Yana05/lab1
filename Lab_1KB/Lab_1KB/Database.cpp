#include "Database.h"
#include <iostream>
#include <fstream>

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
        loadCommonPasswords("top1000.txt");
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
    std::string sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password_hash TEXT NOT NULL, "
        "failed_attempts INTEGER DEFAULT 0, "
        "lock_until INTEGER DEFAULT 0"
        ");";

    if (executeSQL(sql)) {
        std::cout << "Таблица users создана/проверена\n";
        return true;
    }
    return false;
}

User* Database::findUser(const std::string& username) {
    std::string sql = "SELECT id, username, password_hash, failed_attempts, lock_until "
        "FROM users WHERE username = '" + username + "';";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return nullptr;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        User* user = new User();
        user->id = sqlite3_column_int(stmt, 0);
        user->username = (const char*)sqlite3_column_text(stmt, 1);
        user->passwordHash = (const char*)sqlite3_column_text(stmt, 2);
        user->failedAttempts = sqlite3_column_int(stmt, 3);
        user->lockUntil = sqlite3_column_int64(stmt, 4);
        sqlite3_finalize(stmt);
        return user;
    }

    sqlite3_finalize(stmt);
    return nullptr;
}

bool Database::saveUser(const User& user) {
    std::string sql;
    if (user.id == 0) {
        sql = "INSERT INTO users (username, password_hash, failed_attempts, lock_until) "
            "VALUES ('" + user.username + "', '" + user.passwordHash + "', " +
            std::to_string(user.failedAttempts) + ", " +
            std::to_string(user.lockUntil) + ");";
    }
    else {
        sql = "UPDATE users SET "
            "password_hash = '" + user.passwordHash + "', "
            "failed_attempts = " + std::to_string(user.failedAttempts) + ", "
            "lock_until = " + std::to_string(user.lockUntil) + " "
            "WHERE id = " + std::to_string(user.id) + ";";
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
            strftime(buffer, sizeof(buffer), "%H:%M:%S %d.%m.%Y", &timeinfo);
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

bool Database::loadCommonPasswords(const std::string& filePath) {
    // Создаём таблицу, если её нет
    if (!executeSQL("CREATE TABLE IF NOT EXISTS common_passwords ("
        "password TEXT PRIMARY KEY);")) {
        return false;
    }

    // Открываем файл
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cout << "Не удалось открыть файл с частыми паролями: "
            << filePath << "\n";
        return false;
    }

    sqlite3_stmt* stmt;
    const char* sql =
        "INSERT OR IGNORE INTO common_passwords (password) VALUES (?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cout << "Ошибка подготовки запроса: "
            << sqlite3_errmsg(db) << "\n";
        return false;
    }

    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        sqlite3_bind_text(stmt, 1, line.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        count++;
    }
    sqlite3_finalize(stmt);

    std::cout << "Загружено частых паролей: " << count << "\n";
    return true;
}

bool Database::isCommonPassword(const std::string& password) {
    if (!db) return false;

    sqlite3_stmt* stmt;
    const char* sql =
        "SELECT 1 FROM common_passwords WHERE password = ? LIMIT 1;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, password.c_str(), -1, SQLITE_TRANSIENT);
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

bool Database::isOpen() const {
    return db != nullptr;
}