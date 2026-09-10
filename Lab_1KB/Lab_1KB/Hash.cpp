#include "Hash.h"
#include <sstream>

using namespace std;

string Hash::hashPassword(const string& password, const string& salt) {
    unsigned long hash = 5381;
    string combined = password + salt;

    for (char c : combined) {
        hash = ((hash << 5) + hash) ^ c;
        hash ^= (hash >> 16);
    }

    stringstream ss;
    ss << hex << hash;
    return ss.str();
}