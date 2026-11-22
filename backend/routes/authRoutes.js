const express = require("express");
const { promisify } = require("util");
const {
  scrypt: scryptCallback,
  timingSafeEqual
} = require("crypto");
const db = require("../config/db");
const { hashPassword } = require("../utils/passwords");
const {
  authenticate,
  clearSessionCookie,
  setSessionCookie
} = require("../middleware/auth");

const router = express.Router();
const scrypt = promisify(scryptCallback);

router.get("/me", authenticate, (req, res) => {
  res.json({ user: req.user });
});

router.post("/signout", (req, res) => {
  clearSessionCookie(res);
  res.status(204).end();
});

router.post("/signup", async (req, res) => {
  const { name, email, password } = req.body || {};
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
      error: "Use at least 12 letters (A-Z only) for your password."
    });
  }

  try {
    const storedPassword = await hashPassword(password);

    db.query(
      "INSERT INTO users (name, email, password_hash, role, approval_status) VALUES (?, ?, ?, 'student', 'pending')",
      [normalizedName, normalizedEmail, storedPassword],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
              error: "An account with this email already exists."
            });
          }

          console.error("Signup database error:", err.message);
          return res.status(500).json({ error: "Unable to create account." });
        }

        return res.status(201).json({
          message: "Your account has been submitted for administrator approval."
        });
      }
    );
  } catch (err) {
    console.error("Signup password hashing error:", err.message);
    return res.status(500).json({ error: "Unable to create account." });
  }
});

router.post("/signin", async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";

  if (!normalizedEmail || typeof password !== "string") {
    return res.status(400).json({ error: "Enter your email and password." });
  }

  db.query(
    "SELECT id, name, email, password_hash, role, approval_status FROM users WHERE email = ? LIMIT 1",
    [normalizedEmail],
    async (err, results) => {
      if (err) {
        console.error("Signin database error:", err.message);
        return res.status(500).json({ error: "Unable to sign in." });
      }

      const user = results[0];
      if (!user) {
        return res.status(401).json({ error: "Invalid email or password." });
      }

      if (typeof user.password_hash !== "string") {
        console.error("Signin password hash is invalid for user:", user.id);
        return res.status(500).json({ error: "Unable to sign in." });
      }

      const [algorithm, salt, hash] = user.password_hash.split("$");
      if (
        algorithm !== "scrypt" ||
        !/^[a-f\d]{32}$/i.test(salt || "") ||
        !/^[a-f\d]{128}$/i.test(hash || "")
      ) {
        console.error("Signin password hash is invalid for user:", user.id);
        return res.status(500).json({ error: "Unable to sign in." });
      }

      try {
        const passwordHash = await scrypt(password, salt, 64);
        const storedHash = Buffer.from(hash, "hex");
        if (
          passwordHash.length !== storedHash.length ||
          !timingSafeEqual(passwordHash, storedHash)
        ) {
          return res.status(401).json({ error: "Invalid email or password." });
        }

        if (user.approval_status !== "approved") {
          return res.status(403).json({
            error: "Your account is waiting for administrator approval."
          });
        }

        try {
          setSessionCookie(res, user.id);
        } catch (sessionError) {
          console.error("Signin session error:", sessionError.message);
          return res.status(500).json({ error: "Unable to sign in." });
        }

        return res.json({
          message: "Signed in successfully.",
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
          }
        });
      } catch (hashError) {
        console.error("Signin password verification error:", hashError.message);
        return res.status(500).json({ error: "Unable to sign in." });
      }
    }
  );
});

module.exports = router;
