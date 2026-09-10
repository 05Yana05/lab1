#include "AuthSystem.h"
#include <iostream>

using namespace std;

int main() {
    setlocale(LC_ALL, "Russian");

    cout << "СИСТЕМА АУТЕНТИФИКАЦИИ С SQLite\n";
    cout << "Файл БД: users.db\n";
    cout << "Путь: D:\\Users\\Honor\\source\\repos\\Lab_1KB\\users.db\n\n";

    AuthSystem auth("D:\\Users\\Honor\\source\\repos\\Lab_1KB\\users.db");
    auth.showMenu();

    return 0;
}