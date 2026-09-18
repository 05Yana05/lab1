#include "AuthSystem.h"
#include <iostream>
#include <windows.h>
#include <clocale>

using namespace std;

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, ".UTF8");

    cout << "СИСТЕМА АУТЕНТИФИКАЦИИ С SQLite\n";
    cout << "Файл БД: users.db\n";
    cout << "Путь: D:\\Users\\Honor\\source\\repos\\Lab_1KB\\users.db\n\n";

    AuthSystem auth("D:\\Users\\Honor\\source\\repos\\Lab_1KB\\users.db");
    auth.showMenu();

    return 0;
}