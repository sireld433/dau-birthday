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
  if (password && password.length <= 64 && verifyPassword(password)) {
    fails.delete(ip);
    return res.json({ ok: true });
  }

  const r = fails.get(ip) || { count: 0, first: now };
  r.count++;
  fails.set(ip, r);
  res.status(401).json({ ok: false });
});

app.use(express.static(path.join(__dirname, 'public'), { index: 'sndau.html' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🎂 Chạy tại http://localhost:${PORT}`));