#include "User.h"
#include "Hash.h"

User::User() : id(0), username(""), passwordHash(""),
failedAttempts(0), lockUntil(0) {
}

User::User(const std::string& uname, const std::string& pass)
    : id(0), username(uname), failedAttempts(0), lockUntil(0) {
    passwordHash = Hash::hashPassword(pass);
}

bool User::isLocked() const {
    if (lockUntil == 0) return false;
    return time(nullptr) < lockUntil;
}

int User::getRemainingLockTime() const {
    if (lockUntil == 0) return 0;
    time_t now = time(nullptr);
    if (now >= lockUntil) return 0;
    return (int)(lockUntil - now);
}