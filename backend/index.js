const pg = require("pg");

const express = require("express");
const bodyParser = require("body-parser");
const app = express();
const cors = require("cors");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const port = 3000;

const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: 5432,
  connectionTimeoutMillis: 5000,
});

console.log("Connecting...:");

app.use(bodyParser.json());
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

const corsOptions = {
  origin: "http://localhost:8080",
  optionsSuccessStatus: 200,
};

(async () => {
  try {
    const result = await pool.query("SELECT * FROM users");
    for (const user of result.rows) {
      const isHashed = user.password.startsWith("$2b$");

      if (!isHashed) {
        console.log(`Hashing password for user: ${user.user_name}`);
        const hashedPassword = await bcrypt.hash(user.password, saltRounds);

        await pool.query(
          "UPDATE users SET password = $1 WHERE user_name = $2",
          [hashedPassword, user.user_name]
        );
      }
    }

    console.log("All plaintext passwords hashed.");
  } catch (err) {
    console.error("Error hashing passwords:", err);
  }
})();

app.get(
  "/authenticate/:username/:password",
  cors(corsOptions),
  async (request, response) => {
    const username = request.params.username;
    const password = request.params.password;

    const query = "SELECT * FROM users WHERE user_name = $1";
    const values = [username];

    try {
      const results = await pool.query(query, values);
      const user = results.rows[0];

      if (!user) {
        return response.status(401).json({ error: "User not found" });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        response.status(200).json({ success: true, user });
      } else {
        response.status(401).json({ error: "Invalid credentials" });
      }
    } catch (error) {
      console.error("Database error:", error);
      response.status(500).json({ error: "Internal server error" });
    }
  }
);

app.listen(port, () => {
  console.log(`App running on port ${port}.`);
});
