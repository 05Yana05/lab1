// ============================================================================
// HTTP-сервер аутентификации
// ============================================================================

const express = require('express');
const argon2 = require('argon2');
const db = require('./db');

const app = express();
const PORT = 3000;

// Максимальное количество неудачных попыток и длительность блокировки (в секундах)
const MAX_ATTEMPTS = 3;
const LOCK_DURATION = 30;

// Окно свежести timestamp (в секундах)
const TIMESTAMP_WINDOW = 30;

// Список использованных nonce (для защиты от replay-атак)
const usedNonces = new Set();

// Разрешаем принимать JSON в теле запроса
app.use(express.json());

// ----------------------------------------------------------------------------
// Вспомогательные функции
// ----------------------------------------------------------------------------

// Проверка свежести timestamp
function checkFreshness(timestamp) {
    const now = Math.floor(Date.now() / 1000);
    return Math.abs(now - timestamp) <= TIMESTAMP_WINDOW;
}

// Проверка и регистрация nonce (защита от replay)
function checkAndMarkNonce(nonce) {
    if (usedNonces.has(nonce)) {
        return false;
    }
    usedNonces.add(nonce);
    return true;
}

// ----------------------------------------------------------------------------
// POST /register — регистрация нового пользователя
// ----------------------------------------------------------------------------
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Проверка входных данных
    if (!username || !password) {
        return res.json({ status: 'error', message: 'Username and password required' });
    }

    if (username.length < 3) {
        return res.json({ status: 'error', message: 'Username must be at least 3 characters' });
    }

    if (db.userExists(username)) {
        return res.json({ status: 'error', message: 'Username already exists' });
    }

    try {
        // Хешируем пароль через Argon2id
        const passwordHash = await argon2.hash(password);

        // Создаём пользователя
        const userId = db.createUser(username, passwordHash);

        console.log(`[REGISTER OK] username=${username}, id=${userId}`);
        res.json({ status: 'ok', message: `User ${username} registered successfully` });
    }
    catch (err) {
        console.error('[REGISTER ERROR]', err);
        res.json({ status: 'error', message: 'Registration failed' });
    }
});

// ----------------------------------------------------------------------------
// POST /login — вход в систему
// ----------------------------------------------------------------------------
app.post('/login', async (req, res) => {
    const { username, password, timestamp, nonce } = req.body;

    // Проверка входных данных
    if (!username || !password) {
        return res.json({ status: 'error', message: 'Username and password required' });
    }

    if (!timestamp || !nonce) {
        return res.json({ status: 'error', message: 'Timestamp and nonce required' });
    }

    // Проверяем свежесть timestamp (защита от replay)
    if (!checkFreshness(timestamp)) {
        console.log(`[REPLAY] username=${username}, reason=stale timestamp`);
        return res.json({ status: 'error', message: 'Timestamp too old' });
    }

    // Проверяем уникальность nonce (защита от replay)
    if (!checkAndMarkNonce(nonce)) {
        console.log(`[REPLAY] username=${username}, reason=nonce reused, nonce=${nonce}`);
        return res.json({ status: 'error', message: 'Replay detected' });
    }

    // Ищем пользователя
    const user = db.findUser(username);
    if (!user) {
        return res.json({ status: 'error', message: 'User not found' });
    }

    // Проверяем блокировку
    const now = Math.floor(Date.now() / 1000);
    if (user.lock_until > now) {
        const remaining = user.lock_until - now;
        return res.json({
            status: 'error',
            message: `Account locked for ${remaining} seconds`
        });
    }

    try {
        // Проверяем пароль через Argon2id
        const passwordOk = await argon2.verify(user.password_hash, password);

        if (passwordOk) {
            // Успешный вход: сбрасываем счётчик неудачных попыток
            db.updateUser(user.id, { failedAttempts: 0, lockUntil: 0 });
            console.log(`[LOGIN OK] username=${username}`);
            return res.json({ status: 'ok', message: `Welcome, ${username}!` });
        }
        else {
            // Неудачный вход: увеличиваем счётчик
            const newAttempts = user.failed_attempts + 1;
            let lockUntil = 0;

            if (newAttempts >= MAX_ATTEMPTS) {
                lockUntil = now + LOCK_DURATION;
                db.updateUser(user.id, { failedAttempts: newAttempts, lockUntil });
                console.log(`[LOCKED] username=${username}, duration=${LOCK_DURATION}s`);
                return res.json({
                    status: 'error',
                    message: `Too many failed attempts. Account locked for ${LOCK_DURATION} seconds`
                });
            }

            db.updateUser(user.id, { failedAttempts: newAttempts });
            console.log(`[LOGIN FAIL] username=${username}, attempt=${newAttempts}`);
            return res.json({
                status: 'error',
                message: `Wrong password. Attempts left: ${MAX_ATTEMPTS - newAttempts}`
            });
        }
    }
    catch (err) {
        console.error('[LOGIN ERROR]', err);
        res.json({ status: 'error', message: 'Login failed' });
    }
});

// ----------------------------------------------------------------------------
// GET /users — список всех пользователей (для отладки)
// ----------------------------------------------------------------------------
app.get('/users', (req, res) => {
    res.json({ status: 'ok', users: db.allUsers() });
});


// ----------------------------------------------------------------------------
// POST /change-password — смена пароля
// ----------------------------------------------------------------------------
app.post('/change-password', async (req, res) => {
    const { username, oldPassword, newPassword, timestamp, nonce } = req.body;

    // Проверка входных данных
    if (!username || !oldPassword || !newPassword) {
        return res.json({ status: 'error', message: 'Missing required fields' });
    }

    if (!timestamp || !nonce) {
        return res.json({ status: 'error', message: 'Timestamp and nonce required' });
    }

    // Защита от replay
    if (!checkFreshness(timestamp)) {
        console.log(`[REPLAY] username=${username}, reason=stale timestamp`);
        return res.json({ status: 'error', message: 'Timestamp too old' });
    }

    if (!checkAndMarkNonce(nonce)) {
        console.log(`[REPLAY] username=${username}, reason=nonce reused`);
        return res.json({ status: 'error', message: 'Replay detected' });
    }

    // Ищем пользователя
    const user = db.findUser(username);
    if (!user) {
        return res.json({ status: 'error', message: 'User not found' });
    }

    // Проверяем блокировку
    const now = Math.floor(Date.now() / 1000);
    if (user.lock_until > now) {
        return res.json({ status: 'error', message: 'Account locked' });
    }

    try {
        // Проверяем старый пароль
        const oldPasswordOk = await argon2.verify(user.password_hash, oldPassword);
        if (!oldPasswordOk) {
            console.log(`[CHANGE PASSWORD FAIL] username=${username}, reason=wrong old password`);
            return res.json({ status: 'error', message: 'Wrong old password' });
        }

        // Хешируем новый пароль и сохраняем
        const newHash = await argon2.hash(newPassword);
        db.updateUser(user.id, { passwordHash: newHash, failedAttempts: 0, lockUntil: 0 });

        console.log(`[PASSWORD CHANGED] username=${username}`);
        res.json({ status: 'ok', message: 'Password changed successfully' });
    }
    catch (err) {
        console.error('[CHANGE PASSWORD ERROR]', err);
        res.json({ status: 'error', message: 'Change password failed' });
    }
});

// ----------------------------------------------------------------------------
// POST /delete-account — удаление аккаунта
// ----------------------------------------------------------------------------
app.post('/delete-account', async (req, res) => {
    const { username, password, timestamp, nonce } = req.body;

    // Проверка входных данных
    if (!username || !password) {
        return res.json({ status: 'error', message: 'Missing required fields' });
    }

    if (!timestamp || !nonce) {
        return res.json({ status: 'error', message: 'Timestamp and nonce required' });
    }

    // Защита от replay
    if (!checkFreshness(timestamp)) {
        console.log(`[REPLAY] username=${username}, reason=stale timestamp`);
        return res.json({ status: 'error', message: 'Timestamp too old' });
    }

    if (!checkAndMarkNonce(nonce)) {
        console.log(`[REPLAY] username=${username}, reason=nonce reused`);
        return res.json({ status: 'error', message: 'Replay detected' });
    }

    // Ищем пользователя
    const user = db.findUser(username);
    if (!user) {
        return res.json({ status: 'error', message: 'User not found' });
    }

    try {
        // Проверяем пароль
        const passwordOk = await argon2.verify(user.password_hash, password);
        if (!passwordOk) {
            console.log(`[DELETE FAIL] username=${username}, reason=wrong password`);
            return res.json({ status: 'error', message: 'Wrong password' });
        }

        // Удаляем пользователя
        db.deleteUser(username);

        console.log(`[ACCOUNT DELETED] username=${username}`);
        res.json({ status: 'ok', message: 'Account deleted successfully' });
    }
    catch (err) {
        console.error('[DELETE ERROR]', err);
        res.json({ status: 'error', message: 'Delete account failed' });
    }
});


// ----------------------------------------------------------------------------
// Запуск сервера
// ----------------------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`Сервер запущен: http://localhost:${PORT}`);
    console.log('Готов принимать запросы.');
});