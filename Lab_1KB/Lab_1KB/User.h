#pragma once
#include <string>
#include <ctime>

class User {
public:
    int id;
    std::string username;
    std::string passwordHash;
    int failedAttempts;
    time_t lockUntil;

    User();
    User(const std::string& uname, const std::string& pass);

    bool isLocked() const;
    int getRemainingLockTime() const;
};