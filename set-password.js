// Dùng: node set-password.js "matkhaucuaban"
const { setPassword } = require('./db');
const pw = process.argv[2];
if (!pw) {
  console.error('Thiếu mật khẩu');
  process.exit(1);
}
setPassword(pw);
console.log('Đã lưu mật khẩu vào birthday.db');