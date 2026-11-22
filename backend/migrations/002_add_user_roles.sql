ALTER TABLE users
  ADD COLUMN role ENUM('admin', 'student') NOT NULL DEFAULT 'student'
  AFTER password_hash;
