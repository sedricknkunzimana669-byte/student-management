ALTER TABLE users
  ADD COLUMN approval_status ENUM('pending', 'approved') NOT NULL DEFAULT 'approved'
  AFTER role;

UPDATE users
SET approval_status = 'pending'
WHERE role = 'student';
