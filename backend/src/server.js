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
const PORT = Number(process.env.PORT || 8080);
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

function money(value) {
  return Number(value || 0);
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
  db.prepare(`
    INSERT OR IGNORE INTO wallets (user_id, balance)
    VALUES (?, 0)
  `).run(userId);

  return db
    .prepare("SELECT * FROM wallets WHERE user_id=?")
    .get(userId);
}

function addTransaction({
  userId,
  type,
  amount,
  title,
  description = "",
  projectId = null
}) {
  db.prepare(`
    INSERT INTO wallet_transactions
      (user_id, type, amount, title, description, project_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    userId,
    type,
    amount,
    title,
    description,
    projectId
  );
}

function rewardPoints(userId) {
  const row = db.prepare(`
    SELECT COALESCE(SUM(points), 0) AS total
    FROM reward_claims
    WHERE user_id=?
  `).get(userId);

  return Number(row?.total || 0);
}

function claimReward(userId, code, title, points) {
  try {
    const result = db.prepare(`
      INSERT INTO reward_claims
        (user_id, code, title, points)
      VALUES (?, ?, ?, ?)
    `).run(userId, code, title, points);

    return result.changes > 0;
  } catch (err) {
    if (String(err.message).includes("UNIQUE")) {
      return false;
    }
    throw err;
  }
}

/* Health */
app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "Skillora v15",
    database: "sqlite"
  });
});

/* Auth */
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
      INSERT INTO users
        (name, phone, password_hash, role)
      VALUES (?, ?, ?, ?)
    `).run(
      name,
      phone,
      hashPassword(password),
      role
    );

    const user = db
      .prepare("SELECT * FROM users WHERE id=?")
      .get(result.lastInsertRowid);

    ensureWallet(user.id);

    claimReward(
      user.id,
      "welcome",
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

  if (!user || !verifyPassword(password, user.password_hash)) {
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

  res.json({ ok: true });
});

/* User */
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
      error: "نام نمی‌تواند خالی باشد."
    });
  }

  db.prepare(`
    UPDATE users
    SET name=?, bio=?, skills=?
    WHERE id=?
  `).run(
    name,
    bio,
    skills,
    req.auth.sub
  );

  const user = db
    .prepare("SELECT * FROM users WHERE id=?")
    .get(req.auth.sub);

  res.json({
    user: publicUser(user)
  });
});

/* Dashboard */
app.get("/api/dashboard", requireAuth, (req, res) => {
  const userId = req.auth.sub;

  const wallet = ensureWallet(userId);

  let activeProjects = 0;
  let completed = 0;

  if (req.auth.role === "client") {
    activeProjects = db.prepare(`
      SELECT COUNT(*) AS c
      FROM projects
      WHERE client_id=?
      AND status='in_progress'
    `).get(userId).c;

    completed = db.prepare(`
      SELECT COUNT(*) AS c
      FROM projects
      WHERE client_id=?
      AND status='completed'
    `).get(userId).c;
  } else {
    activeProjects = db.prepare(`
      SELECT COUNT(*) AS c
      FROM projects
      WHERE selected_freelancer_id=?
      AND status='in_progress'
    `).get(userId).c;

    completed = db.prepare(`
      SELECT COUNT(*) AS c
      FROM projects
      WHERE selected_freelancer_id=?
      AND status='completed'
    `).get(userId).c;
  }

  const recent = db.prepare(`
    SELECT
      id,
      type,
      amount,
      title,
      description,
      created_at AS createdAt
    FROM wallet_transactions
    WHERE user_id=?
    ORDER BY id DESC
    LIMIT 8
  `).all(userId);

  const claims = db.prepare(`
    SELECT
      id,
      code,
      title,
      points,
      created_at AS createdAt
    FROM reward_claims
    WHERE user_id=?
    ORDER BY id DESC
    LIMIT 8
  `).all(userId);

  res.json({
    stats: {
      wallet: money(wallet.balance),
      rewards: rewardPoints(userId),
      activeProjects: Number(activeProjects || 0),
      completed: Number(completed || 0)
    },
    recent,
    claims
  });
});

/* Projects */
app.get("/api/projects", requireAuth, (req, res) => {
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
      u.name AS clientName,
      CASE
        WHEN pp.id IS NULL THEN 0
        ELSE 1
      END AS paid
    FROM projects p
    JOIN users u
      ON u.id=p.client_id
    LEFT JOIN project_payments pp
      ON pp.project_id=p.id
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
    const category =
      cleanText(req.body.category, 60) || "عمومی";
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

    res.status(201).json({
      project
    });
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

    const project = db.prepare(`
      SELECT *
      FROM projects
      WHERE id=?
    `).get(projectId);

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

      claimReward(
        req.auth.sub,
        "first-application",
        "اولین درخواست همکاری",
        75
      );

      res.status(201).json({
        applicationId: result.lastInsertRowid
      });
    } catch (err) {
      if (String(err.message).includes("UNIQUE")) {
        return res.status(409).json({
          error: "قبلاً برای این پروژه درخواست داده‌اید."
        });
      }

      console.error(err);

      res.status(500).json({
        error: "خطای داخلی سرور."
      });
    }
  }
);

app.get(
  "/api/projects/:id/applications",
  requireAuth,
  (req, res) => {
    const projectId = Number(req.params.id);

    const project = db.prepare(`
      SELECT *
      FROM projects
      WHERE id=?
    `).get(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (req.auth.role === "client") {
      if (project.client_id !== req.auth.sub) {
        return res.status(403).json({
          error: "دسترسی غیرمجاز."
        });
      }
    }

    if (req.auth.role === "freelancer") {
      const own = db.prepare(`
        SELECT
          a.id,
          a.price,
          a.message,
          a.status,
          a.created_at AS createdAt,
          u.id AS freelancerId,
          u.name AS freelancerName,
          u.skills,
          u.rating
        FROM applications a
        JOIN users u
          ON u.id=a.freelancer_id
        WHERE a.project_id=?
        AND a.freelancer_id=?
        ORDER BY a.id DESC
      `).all(
        projectId,
        req.auth.sub
      );

      return res.json({
        applications: own
      });
    }

    const applications = db.prepare(`
      SELECT
        a.id,
        a.price,
        a.message,
        a.status,
        a.created_at AS createdAt,
        u.id AS freelancerId,
        u.name AS freelancerName,
        u.skills,
        u.rating
      FROM applications a
      JOIN users u
        ON u.id=a.freelancer_id
      WHERE a.project_id=?
      ORDER BY a.id DESC
    `).all(projectId);

    res.json({
      applications
    });
  }
);

/* Select freelancer */
app.post(
  "/api/projects/:id/select-freelancer",
  requireAuth,
  requireRole("client"),
  (req, res) => {
    const projectId = Number(req.params.id);
    const freelancerId = Number(req.body.freelancerId);
    const applicationId = Number(req.body.applicationId);

    if (
      !Number.isInteger(projectId) ||
      !Number.isInteger(freelancerId) ||
      !Number.isInteger(applicationId)
    ) {
      return res.status(400).json({
        error: "اطلاعات انتخاب فریلنسر معتبر نیست."
      });
    }

    const project = db.prepare(`
      SELECT *
      FROM projects
      WHERE id=?
    `).get(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (project.client_id !== req.auth.sub) {
      return res.status(403).json({
        error: "دسترسی غیرمجاز."
      });
    }

    if (project.status !== "open") {
      return res.status(409).json({
        error: "این پروژه قبلاً تعیین تکلیف شده است."
      });
    }

    const application = db.prepare(`
      SELECT *
      FROM applications
      WHERE id=?
      AND project_id=?
      AND freelancer_id=?
    `).get(
      applicationId,
      projectId,
      freelancerId
    );

    if (!application) {
      return res.status(404).json({
        error: "درخواست فریلنسر پیدا نشد."
      });
    }

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE projects
        SET
          selected_freelancer_id=?,
          status='in_progress'
        WHERE id=?
      `).run(
        freelancerId,
        projectId
      );

      db.prepare(`
        UPDATE applications
        SET status='accepted'
        WHERE project_id=?
        AND id=?
      `).run(
        projectId,
        applicationId
      );

      db.prepare(`
        UPDATE applications
        SET status='rejected'
        WHERE project_id=?
        AND id<>?
      `).run(
        projectId,
        applicationId
      );
    });

    tx();

    const updated = db.prepare(`
      SELECT *
      FROM projects
      WHERE id=?
    `).get(projectId);

    res.json({
      project: updated,
      selectedApplicationId: applicationId
    });
  }
);

/* Project payment */
app.post(
  "/api/projects/:id/pay",
  requireAuth,
  requireRole("client"),
  (req, res) => {
    const projectId = Number(req.params.id);

    const project = db.prepare(`
      SELECT *
      FROM projects
      WHERE id=?
    `).get(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (project.client_id !== req.auth.sub) {
      return res.status(403).json({
        error: "دسترسی غیرمجاز."
      });
    }

    if (project.status !== "in_progress") {
      return res.status(409).json({
        error: "این پروژه هنوز آماده پرداخت نیست."
      });
    }

    if (!project.selected_freelancer_id) {
      return res.status(409).json({
        error: "ابتدا یک فریلنسر انتخاب کنید."
      });
    }

    const alreadyPaid = db.prepare(`
      SELECT id
      FROM project_payments
      WHERE project_id=?
    `).get(projectId);

    if (alreadyPaid) {
      return res.status(409).json({
        error: "این پروژه قبلاً پرداخت شده است."
      });
    }

    const clientWallet = ensureWallet(req.auth.sub);
    const amount = Number(project.budget);

    if (clientWallet.balance < amount) {
      return res.status(400).json({
        error:
          "موجودی کیف پول کافی نیست. ابتدا کیف پول را شارژ کنید."
      });
    }

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE wallets
        SET balance=balance-?
        WHERE user_id=?
      `).run(
        amount,
        req.auth.sub
      );

      ensureWallet(project.selected_freelancer_id);

      db.prepare(`
        UPDATE wallets
        SET balance=balance+?
        WHERE user_id=?
      `).run(
        amount,
        project.selected_freelancer_id
      );

      addTransaction({
        userId: req.auth.sub,
        type: "debit",
        amount,
        title: "پرداخت پروژه",
        description: project.title,
        projectId
      });

      addTransaction({
        userId: project.selected_freelancer_id,
        type: "credit",
        amount,
        title: "دریافت درآمد پروژه",
        description: project.title,
        projectId
      });

      db.prepare(`
        INSERT INTO project_payments
          (project_id, client_id, freelancer_id, amount)
        VALUES (?, ?, ?, ?)
      `).run(
        projectId,
        req.auth.sub,
        project.selected_freelancer_id,
        amount
      );

      db.prepare(`
        UPDATE projects
        SET status='completed'
        WHERE id=?
      `).run(projectId);

      claimReward(
        project.selected_freelancer_id,
        "first-project",
        "اولین پروژه موفق",
        200
      );
    });

    try {
      tx();

      res.json({
        ok: true,
        message:
          "پرداخت با موفقیت انجام شد و مبلغ به کیف پول فریلنسر منتقل شد."
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "پرداخت انجام نشد."
      });
    }
  }
);

/* Project status */
app.patch(
  "/api/projects/:id/status",
  requireAuth,
  requireRole("client"),
  (req, res) => {
    const projectId = Number(req.params.id);
    const status = cleanText(req.body.status, 30);

    const allowed = [
      "open",
      "in_progress",
      "completed",
      "cancelled"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: "وضعیت پروژه معتبر نیست."
      });
    }

    const project = db.prepare(`
      SELECT *
      FROM projects
      WHERE id=?
    `).get(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (project.client_id !== req.auth.sub) {
      return res.status(403).json({
        error: "دسترسی غیرمجاز."
      });
    }

    if (
      status === "in_progress" &&
      !project.selected_freelancer_id
    ) {
      return res.status(409).json({
        error: "ابتدا یک فریلنسر را انتخاب کنید."
      });
    }

    db.prepare(`
      UPDATE projects
      SET status=?
      WHERE id=?
    `).run(
      status,
      projectId
    );

    res.json({
      project: db.prepare(`
        SELECT *
        FROM projects
        WHERE id=?
      `).get(projectId)
    });
  }
);

/* Wallet */
app.get("/api/wallet", requireAuth, (req, res) => {
  const wallet = ensureWallet(req.auth.sub);

  const transactions = db.prepare(`
    SELECT
      id,
      type,
      amount,
      title,
      description,
      project_id AS projectId,
      created_at AS createdAt
    FROM wallet_transactions
    WHERE user_id=?
    ORDER BY id DESC
    LIMIT 50
  `).all(req.auth.sub);

  res.json({
    balance: Number(wallet.balance || 0),
    transactions
  });
});

/* Demo deposit */
app.post(
  "/api/wallet/demo-deposit",
  requireAuth,
  (req, res) => {
    const amount = Number(req.body.amount);

    if (
      !Number.isInteger(amount) ||
      amount <= 0 ||
      amount > 1000000000
    ) {
      return res.status(400).json({
        error: "مبلغ شارژ معتبر نیست."
      });
    }

    ensureWallet(req.auth.sub);

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE wallets
        SET balance=balance+?
        WHERE user_id=?
      `).run(
        amount,
        req.auth.sub
      );

      addTransaction({
        userId: req.auth.sub,
        type: "credit",
        amount,
        title: "شارژ آزمایشی کیف پول",
        description: "Demo balance"
      });
    });

    tx();

    res.json({
      ok: true,
      balance: ensureWallet(req.auth.sub).balance
    });
  }
);

/* Withdraw */
app.post(
  "/api/wallet/withdraw",
  requireAuth,
  (req, res) => {
    const amount = Number(req.body.amount);

    if (
      !Number.isInteger(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error: "مبلغ برداشت معتبر نیست."
      });
    }

    const wallet = ensureWallet(req.auth.sub);

    if (wallet.balance < amount) {
      return res.status(400).json({
        error: "موجودی کیف پول کافی نیست."
      });
    }

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE wallets
        SET balance=balance-?
        WHERE user_id=?
      `).run(
        amount,
        req.auth.sub
      );

      addTransaction({
        userId: req.auth.sub,
        type: "debit",
        amount,
        title: "برداشت از کیف پول",
        description: "برداشت داخلی Skillora"
      });
    });

    tx();

    res.json({
      ok: true,
      balance: ensureWallet(req.auth.sub).balance
    });
  }
);

/* Rewards */
app.post(
  "/api/rewards/claim",
  requireAuth,
  (req, res) => {
    const code = cleanText(req.body.code, 50);

    const rules = {
      profile: {
        title: "تکمیل پروفایل",
        points: 100
      },
      "first-application": {
        title: "اولین درخواست همکاری",
        points: 75
      },
      "first-project": {
        title: "اولین پروژه موفق",
        points: 200
      }
    };

    const rule = rules[code];

    if (!rule) {
      return res.status(400).json({
        error: "پاداش معتبر نیست."
      });
    }

    const user = db.prepare(`
      SELECT *
      FROM users
      WHERE id=?
    `).get(req.auth.sub);

    if (code === "profile") {
      if (
        !user.name ||
        !user.bio ||
        !user.skills
      ) {
        return res.status(400).json({
          error:
            "برای دریافت این پاداش، پروفایل را کامل کنید."
        });
      }
    }

    if (code === "first-application") {
      const application = db.prepare(`
        SELECT id
        FROM applications
        WHERE freelancer_id=?
        LIMIT 1
      `).get(req.auth.sub);

      if (!application) {
        return res.status(400).json({
          error:
            "هنوز درخواست همکاری ارسال نکرده‌اید."
        });
      }
    }

    if (code === "first-project") {
      const payment = db.prepare(`
        SELECT id
        FROM project_payments
        WHERE freelancer_id=?
        LIMIT 1
      `).get(req.auth.sub);

      if (!payment) {
        return res.status(400).json({
          error:
            "هنوز پروژه موفقی برای شما پرداخت نشده است."
        });
      }
    }

    const claimed = claimReward(
      req.auth.sub,
      code,
      rule.title,
      rule.points
    );

    if (!claimed) {
      return res.status(409).json({
        error: "این پاداش قبلاً دریافت شده است."
      });
    }

    res.json({
      ok: true,
      points: rule.points,
      total: rewardPoints(req.auth.sub)
    });
  }
);

/* Frontend */
app.use(express.static(frontend));

app.get("/", (_req, res) => {
  res.sendFile(
    path.join(frontend, "index.html")
  );
});

app.get("/index.html", (_req, res) => {
  res.sendFile(
    path.join(frontend, "index.html")
  );
});

/* Error handler */
app.use((err, _req, res, _next) => {
  console.error(err);

  res.status(500).json({
    error: "خطای داخلی سرور."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Skillora v15 running at http://localhost:${PORT}`
  );
});
