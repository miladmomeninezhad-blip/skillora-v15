require("dotenv").config?.();

const express = require("express");
const path = require("path");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const db = require("./db");

const {
  COOKIE_NAME,
  hashPassword,
  verifyPassword,
  signToken,
  setSessionCookie,
  requireAuth,
  requireRole
} = require("./auth");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const frontend = path.resolve(__dirname, "../../frontend");

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "تعداد تلاش‌های ورود زیاد است. کمی بعد دوباره تلاش کنید."
  }
});

function cleanText(value, max = 1000) {
  return String(value ?? "").trim().slice(0, max);
}

function normalizePhone(value) {
  return String(value ?? "").replace(/[\s-]/g, "");
}

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    phone: row.phone,
    role: row.role,
    bio: row.bio,
    skills: row.skills,
    rating: row.rating,
    createdAt: row.created_at
  };
}

function ensureWallet(userId) {
  db.prepare(
    "INSERT OR IGNORE INTO wallets (user_id,balance) VALUES (?,0)"
  ).run(userId);
}

function walletBalance(userId) {
  ensureWallet(userId);

  return db
    .prepare("SELECT balance FROM wallets WHERE user_id=?")
    .get(userId).balance;
}

function addTransaction(
  userId,
  type,
  amount,
  title,
  description = "",
  referenceType = null,
  referenceId = null
) {
  db.prepare(`
    INSERT INTO wallet_transactions
      (user_id,type,amount,title,description,reference_type,reference_id)
    VALUES (?,?,?,?,?,?,?)
  `).run(
    userId,
    type,
    amount,
    title,
    description,
    referenceType,
    referenceId
  );
}

function rewardPoints(userId) {
  const row = db
    .prepare(
      "SELECT COALESCE(SUM(points),0) AS points FROM reward_claims WHERE user_id=?"
    )
    .get(userId);

  return row.points || 0;
}

/* Health */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "Skillora v15 Pro",
    database: "sqlite"
  });
});

/* Authentication */

app.post("/api/auth/register", (req, res) => {
  const name = cleanText(req.body.name, 80);
  const phone = normalizePhone(req.body.phone);
  const password = String(req.body.password || "");
  const role = req.body.role;

  if (
    !name ||
    !/^\+?[0-9]{8,15}$/.test(phone) ||
    password.length < 8 ||
    !["client", "freelancer"].includes(role)
  ) {
    return res.status(400).json({
      error:
        "نام، شماره معتبر، رمز حداقل ۸ کاراکتری و نقش معتبر لازم است."
    });
  }

  try {
    const result = db
      .prepare(
        `INSERT INTO users
        (name, phone, password_hash, role)
        VALUES (?, ?, ?, ?)`
      )
      .run(name, phone, hashPassword(password), role);

    const user = db
      .prepare("SELECT * FROM users WHERE id=?")
      .get(result.lastInsertRowid);

    ensureWallet(user.id);

    db.prepare(`
      INSERT OR IGNORE INTO reward_claims
      (user_id,code,title,points)
      VALUES (?,?,?,?)
    `).run(
      user.id,
      "signup",
      "عضویت در Skillora",
      50
    );

    setSessionCookie(res, signToken(user));

    res.status(201).json({
      user: publicUser(user)
    });

  } catch (err) {

    if (String(err.message).includes("UNIQUE")) {
      return res.status(409).json({
        error: "این شماره موبایل قبلاً ثبت شده است."
      });
    }

    console.error(err);

    res.status(500).json({
      error: "خطای داخلی سرور."
    });
  }
});

app.post("/api/auth/login", loginLimiter, (req, res) => {

  const phone = normalizePhone(req.body.phone);
  const password = String(req.body.password || "");

  const user = db
    .prepare("SELECT * FROM users WHERE phone=?")
    .get(phone);

  if (
    !user ||
    !verifyPassword(password, user.password_hash)
  ) {
    return res.status(401).json({
      error: "شماره موبایل یا رمز عبور اشتباه است."
    });
  }

  ensureWallet(user.id);

  setSessionCookie(res, signToken(user));

  res.json({
    user: publicUser(user)
  });
});

app.post("/api/auth/logout", (_req, res) => {

  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    sameSite: "lax",
    path: "/"
  });

  res.json({
    ok: true
  });
});

/* Profile */

app.get("/api/me", requireAuth, (req, res) => {

  const user = db
    .prepare("SELECT * FROM users WHERE id=?")
    .get(req.auth.sub);

  if (!user) {
    return res.status(401).json({
      error: "کاربر پیدا نشد."
    });
  }

  ensureWallet(user.id);

  res.json({
    user: publicUser(user)
  });
});

app.patch("/api/me", requireAuth, (req, res) => {

  const name = cleanText(req.body.name, 80);
  const bio = cleanText(req.body.bio, 1000);
  const skills = cleanText(req.body.skills, 500);

  if (!name) {
    return res.status(400).json({
      error: "نام نمی‌تواند خ
