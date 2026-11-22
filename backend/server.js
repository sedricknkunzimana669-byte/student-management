
require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "http://localhost:5173",
  credentials: true
}));
app.use(express.json());

// Student routes
app.use("/api/students", require("./routes/studentRoutes"));
app.use("/api/auth", require("./routes/authRoutes"));
app.use("/api/admin", require("./routes/adminRoutes"));

app.get("/", (req, res) => {
  res.send("Student Registration API is running!");
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Backend running at http://localhost:${PORT}`);
});
