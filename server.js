const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!DATABASE_URL || !ADMIN_PASSWORD) {
  console.error("Set DATABASE_URL and ADMIN_PASSWORD environment variables.");
  process.exit(1);
}
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
});

function normalizePhone(value) {
  return String(value || "").replace(/[\s()-]/g, "");
}
function validPhone(phone) {
  return /^\+?[0-9]{8,15}$/.test(phone);
}
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}
function equal(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    phone VARCHAR(32) UNIQUE NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
}

app.post("/api/auth/register-or-login", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");
    if (!validPhone(phone)) return res.status(400).json({ error: "شماره موبایل معتبر وارد کن." });
    if (password.length < 8 || password.length > 200)
      return res.status(400).json({ error: "رمز عبور باید حداقل ۸ کاراکتر باشد." });

    const found = await pool.query(
      "SELECT password_salt, password_hash FROM users WHERE phone = $1", [phone]
    );
    if (found.rowCount) {
      const row = found.rows[0];
      if (!equal(hashPassword(password, row.password_salt), row.password_hash))
        return res.status(401).json({ error: "این شماره قبلاً ثبت‌نام کرده؛ رمز عبور اشتباه است." });
      return res.json({ ok: true, mode: "login" });
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const digest = hashPassword(password, salt);
    await pool.query(
      "INSERT INTO users(phone, password_salt, password_hash) VALUES($1,$2,$3)",
      [phone, salt, digest]
    );
    return res.status(201).json({ ok: true, mode: "registered" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "خطای سرور؛ دوباره تلاش کن." });
  }
});

app.get("/api/admin/accounts", async (req, res) => {
  try {
    if (!equal(req.get("x-admin-password") || "", ADMIN_PASSWORD))
      return res.status(401).json({ error: "رمز مدیریت اشتباه است." });
    const result = await pool.query(
      "SELECT phone, created_at FROM users ORDER BY created_at DESC"
    );
    res.json({ accounts: result.rows.map(r => ({
      phone: r.phone, createdAt: r.created_at
    })) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "دریافت فهرست کاربران ناموفق بود." });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true }));
init().then(() => app.listen(PORT, () => console.log("MAN server on " + PORT)))
  .catch(error => { console.error(error); process.exit(1); });
