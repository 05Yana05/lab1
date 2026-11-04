const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = 3000;

const JWT_ACCESS_SECRET = 'access_secret_key_abc';
const JWT_REFRESH_SECRET = 'refresh_secret_xyz';

// Черный список теперь в БД, память для nonce
const usedNonces = new Set();

app.use(express.json());

function checkReplay(nonce, timestamp) {
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 30) return false;
    if (usedNonces.has(nonce)) return false;
    usedNonces.add(nonce);
    return true;
}

// --- MIDDLEWARE ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send("Нет токена");

    // Проверка в базе данных SQLite
    if (db.isBlacklisted(token)) return res.status(401).send("Токен отозван");

    if (!req.body.nonce || !req.body.timestamp) return res.status(400).send("Нет nonce");
    if (!checkReplay(req.body.nonce, req.body.timestamp)) return res.status(400).send("Replay");

    jwt.verify(token, JWT_ACCESS_SECRET, (err, user) => {
        if (err) return res.status(401).send("Токен истек");
        req.user = user;
        next();
    });
}

// --- РЕГИСТРАЦИЯ ---
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ status: 'error', message: 'Логин и пароль обязательны' });
    
    if (db.userExists(username)) {
        return res.status(409).json({ status: 'error', message: 'Пользователь уже существует' });
    }

    try {
        const passwordHash = await argon2.hash(password);
        db.createUser(username, passwordHash);
        res.json({ status: 'ok', message: `Пользователь ${username} зарегистрирован` });
    } catch (err) {
        res.status(500).json({ status: 'error', message: 'Ошибка регистрации' });
    }
});

// --- ВХОД ---
app.post('/login', async (req, res) => {
    const { username, password, nonce, timestamp } = req.body;
    if (!checkReplay(nonce, timestamp)) return res.status(400).json({ error: "Replay" });

    const user = db.findUser(username);
    if (!user) return res.status(401).json({ error: "Неверные данные" });

    const passOk = await argon2.verify(user.password_hash, password);
    if (!passOk) return res.status(401).json({ error: "Неверные данные" });

    const accessToken = jwt.sign({ username }, JWT_ACCESS_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ username }, JWT_REFRESH_SECRET, { expiresIn: '7d' });

    const expiresAt = Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60);
    db.saveRefreshToken(refreshToken, username, expiresAt);

    res.json({ status: 'ok', accessToken, refreshToken });
});

// --- ОБНОВЛЕНИЕ ТОКЕНА ---
app.post('/refresh', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(403).send("Нет токена");

    const savedToken = db.findRefreshToken(refreshToken);
    if (!savedToken) return res.status(403).send("Токен недействителен");

    jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
        if (err) return res.status(403).send("Истек");

        db.deleteRefreshToken(refreshToken);
        
        const newAccess = jwt.sign({ username: user.username }, JWT_ACCESS_SECRET, { expiresIn: '15m' });
        const newRefresh = jwt.sign({ username: user.username }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
        
        db.saveRefreshToken(newRefresh, user.username, Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60));

        res.json({ accessToken: newAccess, refreshToken: newRefresh });
    });
});

// --- ВЫХОД ---
app.post('/logout', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (token) {
        // Добавляем в БД (живет 15 минут)
        const expiresAt = Math.floor(Date.now() / 1000) + 900;
        db.addToBlacklist(token, expiresAt);
    }
    res.json({ status: 'ok' });
});

// --- СМЕНА ПАРОЛЯ ---
app.post('/change-password', authenticateToken, async (req, res) => {
    const username = req.user.username;
    const { oldPassword, newPassword } = req.body; 

    const user = db.findUser(username);
    const oldPassOk = await argon2.verify(user.password_hash, oldPassword);
    if (!oldPassOk) return res.status(401).json({ error: "Неверный старый пароль" });

    const newHash = await argon2.hash(newPassword);
    db.updateUser(user.id, { passwordHash: newHash, failedAttempts: 0, lockUntil: 0 });

    res.json({ status: 'ok', message: 'Пароль успешно изменен' });
});

// --- УДАЛЕНИЕ ---
app.post('/delete-account', authenticateToken, async (req, res) => {
    const username = req.user.username;
    const { password } = req.body;

    const user = db.findUser(username);
    const passOk = await argon2.verify(user.password_hash, password);
    if (!passOk) return res.status(401).json({ error: "Неверный пароль" });

    db.deleteUser(username);
    res.json({ status: 'ok', message: 'Аккаунт удален' });
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Сервер запущен: http://localhost:${PORT}`);
    });
}
module.exports = app;