// Dùng: node set-password.js "matkhaucuaban"
const { setPassword } = require('./db');
const pw = process.argv[2];
if (!pw) {
  console.error('Thiếu mật khẩu. Ví dụ: node set-password.js "matkhau123"');
  process.exit(1);
}
const { salt, hash } = setPassword(pw);
console.log('✅ Đã lưu mật khẩu (dạng hash) vào birthday.db\n');
console.log('Khi deploy lên Render, thêm 2 biến môi trường sau:');
console.log('PASSWORD_SALT=' + salt);
console.log('PASSWORD_HASH=' + hash);