const express = require('express');
const path = require('path');
const { verifyPassword } = require('./db');

const app = express();
app.set('trust proxy', 1); // Render đứng sau proxy, cần để lấy đúng IP
app.use(express.json({ limit: '1kb' }));

// Chống dò mật khẩu: tối đa 5 lần sai / 10 phút / IP
const MAX_FAILS = 5, WINDOW_MS = 10 * 60 * 1000;
const fails = new Map();

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const now = Date.now();
  const rec = fails.get(ip);
  if (rec && now - rec.first > WINDOW_MS) fails.delete(ip);
  const cur = fails.get(ip);
  if (cur && cur.count >= MAX_FAILS) {
    return res.status(429).json({ ok: false });
  }

  const password = typeof req.body.password === 'string' ? req.body.password : '';
  let ok = false;
  try {
    ok = !!password && password.length <= 64 && verifyPassword(password);
  } catch (err) {
    // Lỗi thật của server (ví dụ thiếu biến môi trường và không có SQLite) -> ghi vào Logs
    console.error('LOGIN ERROR:', err.message);
    return res.status(500).json({ ok: false, error: 'server' });
  }
  console.log('LOGIN', ok ? 'OK' : 'WRONG', 'pwlen=' + password.length);
  if (ok) {
    fails.delete(ip);
    return res.json({ ok: true });
  }

  const r = fails.get(ip) || { count: 0, first: now };
  r.count++;
  fails.set(ip, r);
  res.status(401).json({ ok: false });
});

// Chẩn đoán: mở /api/health để xem server đã nhận biến môi trường chưa (không lộ giá trị)
app.get('/api/health', (req, res) => {
  const salt = process.env.PASSWORD_SALT || '';
  const hash = process.env.PASSWORD_HASH || '';
  res.json({
    node: process.version,
    saltLength: salt.length,   // phải là 32
    hashLength: hash.length,   // phải là 128
    saltHasSpace: salt !== salt.trim(),
    hashHasSpace: hash !== hash.trim()
  });
});

app.use(express.static(path.join(__dirname, 'public'), { index: 'sndau.html' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🎂 Chạy tại http://localhost:${PORT}`));