#include "User.h"
#include "Hash.h"
#include <cstdlib>
#include <ctime>

using namespace std;

User::User() : id(0), username(""), salt(""), passwordHash(""), failedAttempts(0), lockUntil(0) {}

User::User(const string& uname, const string& pass)
    : id(0), username(uname), failedAttempts(0), lockUntil(0) {
    salt = generateSalt();
    passwordHash = Hash::hashPassword(pass, salt);
}

string User::generateSalt() {
    string salt;
    srand((unsigned)time(nullptr));
    string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    for (int i = 0; i < 8; i++) {
        salt += chars[rand() % chars.length()];
    }
    return salt;
}

bool User::isLocked() const {
    if (lockUntil == 0) return false;
    time_t now = time(nullptr);
    return now < lockUntil;
}

int User::getRemainingLockTime() const {
    if (lockUntil == 0) return 0;
    time_t now = time(nullptr);
    if (now >= lockUntil) return 0;
    return (int)(lockUntil - now);
}