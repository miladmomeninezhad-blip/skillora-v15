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
  message: { error: "تعداد تلاش‌های ورود زیاد است. کمی بعد دوباره تلاش کنید." }
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

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "Skillora v15",
    database: "sqlite"
  });
});

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
      error: "نام، شماره معتبر، رمز حداقل ۸ کاراکتری و نقش معتبر لازم است."
    });
  }

  try {
    const result = db.prepare(`
      INSERT INTO users (name, phone, password_hash, role)
      VALUES (?, ?, ?, ?)
    `).run(name, phone, hashPassword(password), role);

    const user = db
      .prepare("SELECT * FROM users WHERE id=?")
      .get(result.lastInsertRowid);

    setSessionCookie(res, signToken(user));
    res.status(201).json({ user: publicUser(user) });
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

  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({
      error: "شماره موبایل یا رمز عبور اشتباه است."
    });
  }

  setSessionCookie(res, signToken(user));
  res.json({ user: publicUser(user) });
});

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    sameSite: "lax",
    path: "/"
  });

  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  const user = db
    .prepare("SELECT * FROM users WHERE id=?")
    .get(req.auth.sub);

  if (!user) {
    return res.status(401).json({
      error: "کاربر پیدا نشد."
    });
  }

  res.json({ user: publicUser(user) });
});

app.patch("/api/me", requireAuth, (req, res) => {
  const name = cleanText(req.body.name, 80);
  const bio = cleanText(req.body.bio, 1000);
  const skills = cleanText(req.body.skills, 500);

  if (!name) {
    return res.status(400).json({
      error: "نام نمی‌تواند خالی باشد."
    });
  }

  db.prepare(`
    UPDATE users
    SET name=?, bio=?, skills=?
    WHERE id=?
  `).run(name, bio, skills, req.auth.sub);

  const user = db
    .prepare("SELECT * FROM users WHERE id=?")
    .get(req.auth.sub);

  res.json({ user: publicUser(user) });
});

app.get("/api/projects", requireAuth, (_req, res) => {
  const projects = db.prepare(`
    SELECT
      p.id,
      p.title,
      p.description,
      p.category,
      p.budget,
      p.status,
      p.client_id AS clientId,
      p.selected_freelancer_id AS selectedFreelancerId,
      p.created_at AS createdAt,
      u.name AS clientName
    FROM projects p
    JOIN users u ON u.id=p.client_id
    ORDER BY p.id DESC
  `).all();

  res.json({ projects });
});

app.post(
  "/api/projects",
  requireAuth,
  requireRole("client"),
  (req, res) => {
    const title = cleanText(req.body.title, 120);
    const description = cleanText(req.body.description, 3000);
    const category = cleanText(req.body.category, 60) || "عمومی";
    const budget = Number(req.body.budget);

    if (
      !title ||
      !description ||
      !Number.isInteger(budget) ||
      budget < 0
    ) {
      return res.status(400).json({
        error: "عنوان، توضیحات و بودجه معتبر لازم است."
      });
    }

    const result = db.prepare(`
      INSERT INTO projects
      (client_id, title, description, category, budget)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      req.auth.sub,
      title,
      description,
      category,
      budget
    );

    const project = db
      .prepare("SELECT * FROM projects WHERE id=?")
      .get(result.lastInsertRowid);

    res.status(201).json({ project });
  }
);

app.post(
  "/api/projects/:id/apply",
  requireAuth,
  requireRole("freelancer"),
  (req, res) => {
    const projectId = Number(req.params.id);
    const price = Number(req.body.price);
    const message = cleanText(req.body.message, 1500);

    if (
      !Number.isInteger(projectId) ||
      !Number.isInteger(price) ||
      price < 0
    ) {
      return res.status(400).json({
        error: "پروژه یا مبلغ درخواست معتبر نیست."
      });
    }

    const project = db
      .prepare("SELECT * FROM projects WHERE id=?")
      .get(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (project.status !== "open") {
      return res.status(409).json({
        error: "این پروژه دیگر باز نیست."
      });
    }

    try {
      const result = db.prepare(`
        INSERT INTO applications
        (project_id, freelancer_id, price, message)
        VALUES (?, ?, ?, ?)
      `).run(
        projectId,
        req.auth.sub,
        price,
        message
      );

      res.status(201).json({
        applicationId: result
