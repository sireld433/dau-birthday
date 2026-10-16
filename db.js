const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const db = new Database(path.join(__dirname, 'birthday.db'));
db.exec(`CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  salt TEXT NOT NULL,
  hash TEXT NOT NULL
)`);

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function setPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare(`INSERT INTO secrets (id, salt, hash) VALUES (1, ?, ?)
              ON CONFLICT(id) DO UPDATE SET salt = excluded.salt, hash = excluded.hash`)
    .run(salt, hashPassword(password, salt));
}

function verifyPassword(password) {
  const row = db.prepare('SELECT salt, hash FROM secrets WHERE id = 1').get();
  if (!row) return false;
  const a = Buffer.from(hashPassword(password, row.salt), 'hex');
  const b = Buffer.from(row.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = { setPassword, verifyPassword };