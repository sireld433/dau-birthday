const crypto = require('crypto');
const path = require('path');

// SQLite chỉ được nạp khi cần (chạy trên máy). Trên Render dùng biến môi trường nên không cần.
let _db = null;
function getDb() {
  if (_db) return _db;
  const Database = require('better-sqlite3');
  _db = new Database(path.join(__dirname, 'birthday.db'));
  _db.exec(`CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt TEXT NOT NULL,
    hash TEXT NOT NULL
  )`);
  return _db;
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

// Ưu tiên biến môi trường (khi deploy), nếu không có thì đọc SQLite (khi chạy local)
function getSecret() {
  if (process.env.PASSWORD_SALT && process.env.PASSWORD_HASH) {
    return { salt: process.env.PASSWORD_SALT, hash: process.env.PASSWORD_HASH };
  }
  return getDb().prepare('SELECT salt, hash FROM secrets WHERE id = 1').get();
}

function setPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  getDb().prepare(`INSERT INTO secrets (id, salt, hash) VALUES (1, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET salt = excluded.salt, hash = excluded.hash`)
    .run(salt, hash);
  return { salt, hash };
}

function verifyPassword(password) {
  const row = getSecret();
  if (!row) return false;
  const a = Buffer.from(hashPassword(password, row.salt), 'hex');
  const b = Buffer.from(row.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = { setPassword, verifyPassword, getSecret };