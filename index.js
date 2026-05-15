const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;


// Middleware
app.use(cors());
app.use(express.json());

// Database
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("DB Error", err);
  } else {
    console.log("Connected to SQLite database");
  }
});

// Create table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    streak INTEGER DEFAULT 0,
    last_login TEXT
  )
`);

// ---------------- SIGNUP ----------------
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (email, password, streak) VALUES (?, ?, ?)",
    [email, hashedPassword, 0],
    (err) => {
      if (err) {
        return res.status(400).json({ message: "User already exists" });
      }
      res.json({ message: "Signup successful" });
    }
  );
});

// ---------------- LOGIN ----------------
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, user) => {
      if (err) return res.status(500).json({ message: "Database error" });

      if (!user)
        return res.status(401).json({ message: "Invalid credentials" });

      const match = await bcrypt.compare(password, user.password);

      if (!match)
        return res.status(401).json({ message: "Invalid credentials" });

      // ----- STREAK LOGIC -----
      const today = new Date().toISOString().split("T")[0];
      let streak = user.streak;

      if (user.last_login === today) {
        // same day → do nothing
      } else {
        streak += 1;
        db.run(
          "UPDATE users SET streak = ?, last_login = ? WHERE id = ?",
          [streak, today, user.id]
        );
      }

      res.json({
        message: "Login successful",
        userId: user.id,
        streak: streak,
      });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
