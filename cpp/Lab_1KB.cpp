#include "AuthSystem.h"
#include <iostream>
#include <windows.h>
#include <clocale>

using namespace std;

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, ".UTF8");

    cout << "СИСТЕМА АУТЕНТИФИКАЦИИ С HTTP-СЕРВЕРОМ\n";
    cout << "Сервер: http://localhost:3000\n\n";

    AuthSystem auth;
    auth.showMenu();

    return 0;
}