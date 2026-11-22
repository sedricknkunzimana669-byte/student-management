const express = require("express");
const db = require("../config/db");
const { authenticate, requireAdmin } = require("../middleware/auth");
const { hashPassword } = require("../utils/passwords");

const router = express.Router();
router.use(authenticate, requireAdmin);

router.get("/accounts", (req, res) => {
  const sql = `
    SELECT
      users.id,
      users.name,
      users.email,
      users.role,
      users.approval_status,
      users.created_at,
      EXISTS (
        SELECT 1
        FROM students
        WHERE LOWER(students.email) COLLATE utf8mb4_unicode_ci =
          LOWER(users.email) COLLATE utf8mb4_unicode_ci
      ) AS has_registration
    FROM users
    ORDER BY users.created_at DESC, users.id DESC
  `;

  db.query(sql, (err, accounts) => {
    if (err) {
      console.error("Account list database error:", err.message);
      return res.status(500).json({ error: "Unable to load accounts." });
    }

    return res.json(accounts);
  });
});

router.post("/accounts", async (req, res) => {
  const { name, email, password, role } = req.body || {};
  const normalizedName = typeof name === "string" ? name.trim() : "";
  const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";

  if (!normalizedName || normalizedName.length > 255) {
    return res.status(400).json({ error: "Enter a name of 1 to 255 characters." });
  }

  if (
    normalizedEmail.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
  ) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  if (typeof password !== "string" || !/^[A-Za-z]{12,}$/.test(password)) {
    return res.status(400).json({
      error: "Use at least 12 letters (A-Z only) for the password."
    });
  }

  if (!["admin", "student"].includes(role)) {
    return res.status(400).json({ error: "Choose a valid account role." });
  }

  try {
    const passwordHash = await hashPassword(password);
    const sql = `
      INSERT INTO users (name, email, password_hash, role, approval_status)
      VALUES (?, ?, ?, ?, 'pending')
    `;
    db.query(
      sql,
      [normalizedName, normalizedEmail, passwordHash, role],
      (err, result) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
              error: "An account with this email already exists."
            });
          }

          console.error("Account creation database error:", err.message);
          return res.status(500).json({ error: "Unable to create account." });
        }

        return res.status(201).json({
          message: "Account created and submitted for approval.",
          id: result.insertId
        });
      }
    );
  } catch (error) {
    console.error("Account creation password hashing error:", error.message);
    return res.status(500).json({ error: "Unable to create account." });
  }
});

router.put("/accounts/:id/approval", (req, res) => {
  const accountId = req.params.id;
  const { approval_status: approvalStatus } = req.body || {};

  if (!/^[1-9]\d*$/.test(accountId)) {
    return res.status(400).json({ error: "Enter a valid account ID." });
  }

  if (!["approved", "rejected"].includes(approvalStatus)) {
    return res.status(400).json({ error: "Choose approve or reject." });
  }

  if (approvalStatus === "approved") {
    return db.query(
      "UPDATE users SET approval_status = 'approved' WHERE id = ? AND approval_status = 'pending'",
      [accountId],
      (err, result) => {
        if (err) {
          console.error("Account approval database error:", err.message);
          return res.status(500).json({ error: "Unable to approve account." });
        }

        if (result.affectedRows) {
          return res.json({
            message: "Account approved. The user can now sign in."
          });
        }

        return db.query(
          "SELECT approval_status FROM users WHERE id = ? LIMIT 1",
          [accountId],
          (lookupErr, accounts) => {
            if (lookupErr) {
              console.error("Account approval lookup error:", lookupErr.message);
              return res.status(500).json({ error: "Unable to approve account." });
            }

            if (!accounts.length) {
              return res.status(404).json({ error: "Account not found." });
            }

            if (accounts[0].approval_status === "approved") {
              return res.json({ message: "Account is already approved." });
            }

            return res.status(409).json({
              error: "The account could not be approved. Refresh and try again."
            });
          }
        );
      }
    );
  }

  db.query(
    "DELETE FROM users WHERE id = ? AND id <> ? AND approval_status = 'pending'",
    [accountId, req.user.id],
    (err, result) => {
      if (err) {
        console.error("Account rejection database error:", err.message);
        return res.status(500).json({ error: "Unable to reject account." });
      }

      if (result.affectedRows) {
        return res.json({
          message: "Account rejected and deleted. Any student registration was kept."
        });
      }

      return db.query(
        "SELECT approval_status FROM users WHERE id = ? LIMIT 1",
        [accountId],
        (lookupErr, accounts) => {
          if (lookupErr) {
            console.error("Account rejection lookup error:", lookupErr.message);
            return res.status(500).json({ error: "Unable to reject account." });
          }

          if (!accounts.length) {
            return res.status(404).json({ error: "Account not found." });
          }

          if (accounts[0].approval_status === "approved") {
            return res.status(409).json({
              error: "Only pending accounts can be rejected."
            });
          }

          return res.status(409).json({
            error: "The account could not be rejected. Refresh and try again."
          });
        }
      );
    }
  );
});

router.put("/accounts/:id/role", (req, res) => {
  const accountId = req.params.id;
  const { role } = req.body || {};

  if (!/^[1-9]\d*$/.test(accountId)) {
    return res.status(400).json({ error: "Enter a valid account ID." });
  }

  if (!["admin", "student"].includes(role)) {
    return res.status(400).json({ error: "Choose a valid account role." });
  }

  if (String(req.user.id) === accountId && role !== "admin") {
    return res.status(403).json({ error: "You cannot remove your own administrator access." });
  }

  const sql = `
    UPDATE users
    SET role = ?
    WHERE id = ?
      AND (
        role <> 'admin'
        OR ? = 'admin'
        OR (
          SELECT admin_count
          FROM (SELECT COUNT(*) AS admin_count FROM users WHERE role = 'admin') AS admins
        ) > 1
      )
  `;

  db.query(sql, [role, accountId, role], (err, result) => {
    if (err) {
      console.error("Account role database error:", err.message);
      return res.status(500).json({ error: "Unable to update account role." });
    }

    if (result.affectedRows) {
      return res.json({ message: "Account role updated successfully." });
    }

    return db.query(
      "SELECT role FROM users WHERE id = ? LIMIT 1",
      [accountId],
      (lookupErr, accounts) => {
        if (lookupErr) {
          console.error("Account role lookup error:", lookupErr.message);
          return res.status(500).json({ error: "Unable to update account role." });
        }

        if (!accounts.length) {
          return res.status(404).json({ error: "Account not found." });
        }

        if (accounts[0].role === role) {
          return res.json({ message: "Account role is unchanged." });
        }

        return res.status(409).json({
          error: "The last administrator cannot be demoted."
        });
      }
    );
  });
});

router.delete("/accounts/:id", (req, res) => {
  const accountId = req.params.id;

  if (!/^[1-9]\d*$/.test(accountId)) {
    return res.status(400).json({ error: "Enter a valid account ID." });
  }

  if (String(req.user.id) === accountId) {
    return res.status(403).json({ error: "You cannot delete your own account." });
  }

  const sql = `
    DELETE FROM users
    WHERE id = ?
      AND NOT EXISTS (
        SELECT 1
        FROM students
        WHERE LOWER(students.email) COLLATE utf8mb4_unicode_ci =
          LOWER(users.email) COLLATE utf8mb4_unicode_ci
      )
      AND (
        role <> 'admin'
        OR (
          SELECT admin_count
          FROM (SELECT COUNT(*) AS admin_count FROM users WHERE role = 'admin') AS admins
        ) > 1
      )
  `;

  db.query(sql, [accountId], (err, result) => {
    if (err) {
      console.error("Account deletion database error:", err.message);
      return res.status(500).json({ error: "Unable to delete account." });
    }

    if (result.affectedRows) {
      return res.json({ message: "Account deleted successfully." });
    }

    db.query(
      "SELECT id, email, role FROM users WHERE id = ? LIMIT 1",
      [accountId],
      (lookupErr, accounts) => {
        if (lookupErr) {
          console.error("Account deletion lookup error:", lookupErr.message);
          return res.status(500).json({ error: "Unable to delete account." });
        }

        if (!accounts.length) {
          return res.status(404).json({ error: "Account not found." });
        }

        const account = accounts[0];
        db.query(
          "SELECT 1 FROM students WHERE LOWER(email) = LOWER(?) LIMIT 1",
          [account.email],
          (registrationErr, registrations) => {
            if (registrationErr) {
              console.error("Account registration lookup error:", registrationErr.message);
              return res.status(500).json({ error: "Unable to delete account." });
            }

            if (registrations.length) {
              return res.status(409).json({
                error: "Delete the student registration before deleting this account."
              });
            }

            if (account.role === "admin") {
              return db.query(
                "SELECT COUNT(*) AS admin_count FROM users WHERE role = 'admin'",
                (countErr, rows) => {
                  if (countErr) {
                    console.error("Administrator count error:", countErr.message);
                    return res.status(500).json({ error: "Unable to delete account." });
                  }

                  if (rows[0].admin_count <= 1) {
                    return res.status(409).json({
                      error: "The last administrator account cannot be deleted."
                    });
                  }

                  return res.status(409).json({
                    error: "The account could not be deleted. Refresh and try again."
                  });
                }
              );
            }

            return res.status(409).json({
              error: "The account could not be deleted. Refresh and try again."
            });
          }
        );
      }
    );
  });
});

module.exports = router;
