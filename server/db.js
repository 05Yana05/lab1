// ============================================================================
// Работа с базой данных SQLite
// ============================================================================

const Database = require('better-sqlite3');
const path = require('path');

// База будет лежать в той же папке, что и скрипт
const db = new Database(path.join(__dirname, 'users.db'));

// Включаем режим WAL для лучшей производительности
db.pragma('journal_mode = WAL');

// Создаём таблицы, если их нет
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        lock_until INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS blacklist (
        token TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
    );
`);

console.log('База данных готова: users.db');

// Экспортируем объект с методами для работы с БД
module.exports = {
    // --- ПОЛЬЗОВАТЕЛИ ---
    findUser(username) {
        const stmt = db.prepare(`
            SELECT id, username, password_hash, failed_attempts, lock_until
            FROM users WHERE username = ?
        `);
        return stmt.get(username);
    },

    createUser(username, passwordHash) {
        const stmt = db.prepare(`
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        `);
        const result = stmt.run(username, passwordHash);
        return result.lastInsertRowid;
    },

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

    deleteUser(username) {
        const stmt = db.prepare('DELETE FROM users WHERE username = ?');
        return stmt.run(username).changes > 0;
    },

    userExists(username) {
        const stmt = db.prepare('SELECT 1 FROM users WHERE username = ? LIMIT 1');
        return stmt.get(username) !== undefined;
    },

    allUsers() {
        const stmt = db.prepare('SELECT id, username, failed_attempts, lock_until FROM users');
        return stmt.all();
    },

    // --- REFRESH-ТОКЕНЫ ---
    saveRefreshToken(token, username, expiresAt) {
        const stmt = db.prepare('INSERT INTO refresh_tokens (token, username, expires_at) VALUES (?, ?, ?)');
        stmt.run(token, username, expiresAt);
    },

    findRefreshToken(token) {
        const stmt = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?');
        return stmt.get(token);
    },

    deleteRefreshToken(token) {
        const stmt = db.prepare('DELETE FROM refresh_tokens WHERE token = ?');
        stmt.run(token);
    },

    // --- BLACKLIST ---
    addToBlacklist(token, expiresAt) {
        const stmt = db.prepare('INSERT OR REPLACE INTO blacklist (token, expires_at) VALUES (?, ?)');
        stmt.run(token, expiresAt);
    },

    isBlacklisted(token) {
        const now = Math.floor(Date.now() / 1000);
        const stmt = db.prepare('SELECT 1 FROM blacklist WHERE token = ? AND expires_at > ?');
        return stmt.get(token, now) !== undefined;
    },

    cleanupBlacklist() {
        const now = Math.floor(Date.now() / 1000);
        const stmt = db.prepare('DELETE FROM blacklist WHERE expires_at < ?');
        stmt.run(now);
    }
};