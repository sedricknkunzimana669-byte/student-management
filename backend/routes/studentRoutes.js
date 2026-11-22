const express = require("express");
const router = express.Router();
const db = require("../config/db");
const { authenticate, requireAdmin } = require("../middleware/auth");

router.use(authenticate);

router.get("/", (req, res) => {
  const sql = req.user.role === "admin"
    ? "SELECT * FROM students ORDER BY id DESC"
    : "SELECT * FROM students WHERE LOWER(email) = ? ORDER BY id DESC";
  const values = req.user.role === "admin" ? [] : [req.user.email];

  db.query(sql, values, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

router.post("/", (req, res) => {
  const { name, email, phone, gender, course, address } = req.body || {};
  const isStudent = req.user.role === "student";
  const studentName = isStudent ? req.user.name : name;
  const studentEmail = isStudent ? req.user.email : email;

  if (
    isStudent &&
    (typeof course !== "string" ||
      !course.trim() ||
      !["Male", "Female"].includes(gender))
  ) {
    return res.status(400).json({ error: "Enter a course and select a gender." });
  }

  const insertStudent = () => {
    const sql = `
      INSERT INTO students (name, email, phone, gender, course, address)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [studentName, studentEmail, phone, gender, course, address],
      (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        res.status(201).json({
          message: "Student registered successfully",
          id: result.insertId
        });
      }
    );
  };

  if (!isStudent) {
    return requireAdmin(req, res, insertStudent);
  }

  db.query(
    "SELECT id FROM students WHERE LOWER(email) = LOWER(?) LIMIT 1",
    [studentEmail],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length) {
        return res.status(409).json({
          error: "A registration already exists for your account."
        });
      }

      return insertStudent();
    }
  );
});

router.put("/:id", requireAdmin, (req, res) => {
  const { name, email, phone, gender, course, address } = req.body;

  const sql = `
    UPDATE students
    SET name=?, email=?, phone=?, gender=?, course=?, address=?
    WHERE id=?
  `;

  db.query(
    sql,
    [name, email, phone, gender, course, address, req.params.id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      if (result.affectedRows === 0) {
        return db.query(
          "SELECT id FROM students WHERE id = ?",
          [req.params.id],
          (lookupErr, rows) => {
            if (lookupErr) {
              return res.status(500).json({ error: lookupErr.message });
            }

            if (rows.length === 0) {
              return res.status(404).json({ message: "Student not found" });
            }

            return res.json({ message: "Student updated successfully" });
          }
        );
      }

      res.json({ message: "Student updated successfully" });
    }
  );
});

router.delete("/:id", requireAdmin, (req, res) => {
  db.query("DELETE FROM students WHERE id=?", [req.params.id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Student not found" });
    }

    res.json({ message: "Student deleted successfully" });
  });
});

module.exports = router;
