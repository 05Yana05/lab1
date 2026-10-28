const test = require('node:test');
const assert = require('node:assert');
const request = require('supertest');

process.env.DB_PATH = ':memory:';

const app = require('../server');
const db = require('../db');

function nowSec() {
    return Math.floor(Date.now() / 1000);
}

function uniqueNonce() {
    return Math.random().toString(36).slice(2, 18);
}

test.beforeEach(() => {
    db._db.exec('DELETE FROM users');
});

// ============================================================================
// POST /register
// ============================================================================

test('register: успешная регистрация', async () => {
    const res = await request(app)
        .post('/register')
        .send({ username: 'alice', password: 'StrongPass1' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'ok');
});

test('register: пустые поля → 400', async () => {
    const res = await request(app)
        .post('/register')
        .send({ username: '', password: '' });

    assert.strictEqual(res.status, 400);
});

test('register: короткий логин → 400', async () => {
    const res = await request(app)
        .post('/register')
        .send({ username: 'ab', password: 'StrongPass1' });

    assert.strictEqual(res.status, 400);
});

// ============================================================================
// POST /login
// ============================================================================

test('login: успешный вход', async () => {
    await request(app).post('/register').send({
        username: 'dave', password: 'StrongPass1'
    });

    const res = await request(app).post('/login').send({
        username: 'dave',
        password: 'StrongPass1',
        timestamp: nowSec(),
        nonce: uniqueNonce(),
    });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'ok');
});

test('login: неверный пароль → 401', async () => {
    await request(app).post('/register').send({
        username: 'dave', password: 'StrongPass1'
    });

    const res = await request(app).post('/login').send({
        username: 'dave',
        password: 'WrongPass',
        timestamp: nowSec(),
        nonce: uniqueNonce(),
    });

    assert.strictEqual(res.status, 401);
});