// ============================================================================
// Работа с базой данных SQLite
// ============================================================================

const Database = require('better-sqlite3');
const path = require('path');

// База будет лежать в той же папке, что и скрипт, файл users.db
const db = new Database(path.join(__dirname, 'users.db'));

// Включаем режим WAL для лучшей производительности
db.pragma('journal_mode = WAL');

// Создаём таблицу пользователей, если её нет
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        lock_until INTEGER DEFAULT 0
    );
`);

console.log('База данных готова: users.db');

// Экспортируем объект с методами для работы с БД
module.exports = {
    // Найти пользователя по логину
    findUser(username) {
        const stmt = db.prepare(`
            SELECT id, username, password_hash, failed_attempts, lock_until
            FROM users WHERE username = ?
        `);
        return stmt.get(username);
    },

    // Создать нового пользователя
    createUser(username, passwordHash) {
        const stmt = db.prepare(`
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        `);
        const result = stmt.run(username, passwordHash);
        return result.lastInsertRowid;
    },

    // Обновить данные пользователя (попытки, блокировка, пароль)
    updateUser(id, { passwordHash, failedAttempts, lockUntil }) {
        const stmt = db.prepare(`
            UPDATE users
            SET password_hash = COALESCE(?, password_hash),
                failed_attempts = COALESCE(?, failed_attempts),
                lock_until = COALESCE(?, lock_until)
            WHERE id = ?
        `);
        stmt.run(passwordHash, failedAttempts, lockUntil, id);
    },

    // Удалить пользователя
    deleteUser(username) {
        const stmt = db.prepare('DELETE FROM users WHERE username = ?');
        return stmt.run(username).changes > 0;
    },

    // Проверить, существует ли пользователь
    userExists(username) {
        const stmt = db.prepare('SELECT 1 FROM users WHERE username = ? LIMIT 1');
        return stmt.get(username) !== undefined;
    },

    // Получить всех пользователей (для отладки)
    allUsers() {
        const stmt = db.prepare('SELECT id, username, failed_attempts, lock_until FROM users');
        return stmt.all();
    }
};