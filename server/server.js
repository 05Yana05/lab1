// ============================================================================
// HTTP-сервер аутентификации с JWT
// ============================================================================

require('dotenv').config();
const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = 3000;

const MAX_ATTEMPTS = 3;
const LOCK_DURATION = 30;
const TIMESTAMP_WINDOW = 30;

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_123';
const JWT_EXPIRES_IN = '15m';

const usedNonces = new Map();

app.use(express.json());

// ----------------------------------------------------------------------------
// Middleware (Охранник)
// ----------------------------------------------------------------------------
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ status: 'error', code: 'NO_TOKEN', message: 'Требуется токен' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ status: 'error', code: 'INVALID_TOKEN', message: 'Недействительный или истекший токен' });
        }
        req.user = user;
        next();
    });
}

// ----------------------------------------------------------------------------
// Вспомогательные функции
// ----------------------------------------------------------------------------
function checkFreshness(timestamp) {
    const now = Math.floor(Date.now() / 1000);
    return Math.abs(now - timestamp) <= TIMESTAMP_WINDOW;
}

function checkAndMarkNonce(nonce) {
    const now = Math.floor(Date.now() / 1000);
    for (const [n, ts] of usedNonces) {
        if (now - ts > 60) usedNonces.delete(n);
    }
    if (usedNonces.has(nonce)) return false;
    usedNonces.set(nonce, now);
    return true;
}

function utf8Length(str) { return [...str].length; }

const KEYBOARD_PATTERNS = [
    'qwertyuiop', 'qwerty', 'qwert', 'werty', 'asdfghjkl', 'asdfgh', 'asdf', 'sdfg',
    'zxcvbnm', 'zxcvbn', 'zxcvb', 'xcvbn', '1234567890', '123456789', '12345678',
    '1234567', '123456', '12345', '1qaz2wsx', 'qazwsx', '1q2w3e', '1q2w3e4r',
    'q1w2e3', 'q1w2e3r4', '1qaz', '2wsx', '3edc', '4rfv', 'zaq1', 'xsw2', 'cde3', 'vfr4',
    'qqq', 'www', 'eee', 'aaa', 'zzz', '111', '000',
];

function containsKeyboardPattern(input) {
    if (!input) return false;
    const lower = input.toLowerCase();
    return KEYBOARD_PATTERNS.some((p) => lower.includes(p));
}

function hasRepeatedChars(input) { return /(.)\1\1/.test(input); }
function containsYear(input) { return /(19|20)\d{2}/.test(input); }

const RESERVED_USERNAMES = ['admin', 'root', 'system', 'user', 'test'];
function isReservedUsername(username) { return RESERVED_USERNAMES.includes(username.toLowerCase()); }

function validateUsername(username) {
    if (!username) return 'Логин обязателен';
    if (utf8Length(username) < 3) return 'Логин должен быть не короче 3 символов';
    if (containsKeyboardPattern(username)) return 'Логин содержит очевидную клавиатурную последовательность';
    if (isReservedUsername(username)) return `Логин '${username}' зарезервирован`;
    return null;
}

function validatePassword(password) {
    if (!password) return 'Пароль не может быть пустым';
    if (containsKeyboardPattern(password)) return 'Пароль содержит очевидную клавиатурную последовательность';
    if (hasRepeatedChars(password)) return 'Пароль содержит три одинаковых символа подряд';
    if (containsYear(password)) return 'Пароль содержит год — слишком предсказуемо';
    return null;
}

// ----------------------------------------------------------------------------
// Роуты
// ----------------------------------------------------------------------------

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ status: 'error', message: 'Логин и пароль обязательны' });

    const usernameError = validateUsername(username);
    if (usernameError) return res.status(400).json({ status: 'error', message: usernameError });

    const passwordError = validatePassword(password);
    if (passwordError) return res.status(400).json({ status: 'error', message: passwordError });

    if (db.userExists(username)) return res.status(409).json({ status: 'error', message: 'Пользователь с таким логином уже существует' });

    try {
        const passwordHash = await argon2.hash(password);
        db.createUser(username, passwordHash);
        res.json({ status: 'ok', message: `Пользователь ${username} успешно зарегистрирован` });
    } catch (err) {
        res.status(500).json({ status: 'error', message: 'Ошибка регистрации' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password, timestamp, nonce } = req.body;

    if (!username || !password) return res.status(400).json({ status: 'error', message: 'Логин и пароль обязательны' });
    if (!timestamp || !nonce) return res.status(400).json({ status: 'error', message: 'Требуется timestamp и nonce' });

    if (!checkFreshness(timestamp)) return res.status(400).json({ status: 'error', code: 'STALE_TIMESTAMP', message: 'Запрос устарел' });
    if (!checkAndMarkNonce(nonce)) return res.status(400).json({ status: 'error', code: 'REPLAY', message: 'Обнаружен повтор запроса' });

    const user = db.findUser(username);
    if (!user) return res.status(401).json({ status: 'error', code: 'BAD_CREDENTIALS', message: 'Неверный логин или пароль' });

    const now = Math.floor(Date.now() / 1000);
    if (user.lock_until > now) {
        return res.status(423).json({ status: 'error', code: 'LOCKED', message: `Аккаунт заблокирован на ${user.lock_until - now} секунд` });
    }

    try {
        const passwordOk = await argon2.verify(user.password_hash, password);

        if (passwordOk) {
            db.updateUser(user.id, { failedAttempts: 0, lockUntil: 0 });
            
            const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

            return res.json({ status: 'ok', token: token, message: `Добро пожаловать, ${username}!` });
        }

        const newAttempts = user.failed_attempts + 1;
        if (newAttempts >= MAX_ATTEMPTS) {
            const lockUntil = now + LOCK_DURATION;
            db.updateUser(user.id, { failedAttempts: newAttempts, lockUntil });
            return res.status(423).json({ status: 'error', code: 'LOCKED', message: `Слишком много попыток. Блокировка на ${LOCK_DURATION} сек.` });
        }

        db.updateUser(user.id, { failedAttempts: newAttempts });
        return res.status(401).json({ status: 'error', code: 'BAD_CREDENTIALS', message: `Неверный пароль. Осталось попыток: ${MAX_ATTEMPTS - newAttempts}` });

    } catch (err) {
        res.status(500).json({ status: 'error', message: 'Ошибка входа' });
    }
});

app.post('/change-password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const username = req.user.username;

    if (!oldPassword || !newPassword) return res.status(400).json({ status: 'error', message: 'Не все поля заполнены' });

    const passwordError = validatePassword(newPassword);
    if (passwordError) return res.status(400).json({ status: 'error', message: passwordError });

    const user = db.findUser(username);
    if (!user) return res.status(401).json({ status: 'error', message: 'Пользователь не найден' });

    try {
        const oldPasswordOk = await argon2.verify(user.password_hash, oldPassword);
        if (!oldPasswordOk) return res.status(401).json({ status: 'error', message: 'Неверный старый пароль' });

        const newHash = await argon2.hash(newPassword);
        db.updateUser(user.id, { passwordHash: newHash, failedAttempts: 0, lockUntil: 0 });

        res.json({ status: 'ok', message: 'Пароль успешно изменён' });
    } catch (err) {
        res.status(500).json({ status: 'error', message: 'Не удалось изменить пароль' });
    }
});

app.post('/delete-account', authenticateToken, async (req, res) => {
    const { password } = req.body;
    const username = req.user.username;

    if (!password) return res.status(400).json({ status: 'error', message: 'Пароль обязателен' });

    const user = db.findUser(username);
    if (!user) return res.status(401).json({ status: 'error', message: 'Пользователь не найден' });

    try {
        const passwordOk = await argon2.verify(user.password_hash, password);
        if (!passwordOk) return res.status(401).json({ status: 'error', message: 'Неверный пароль' });

        db.deleteUser(username);
        res.json({ status: 'ok', message: 'Аккаунт успешно удалён' });
    } catch (err) {
        res.status(500).json({ status: 'error', message: 'Не удалось удалить аккаунт' });
    }
});

app.get('/users', (req, res) => {
    res.json({ status: 'ok', users: db.allUsers() });
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Сервер запущен: http://localhost:${PORT}`);
    });
}
module.exports = app;