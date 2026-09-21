require("dotenv").config();

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

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

function cleanText(value, max = 1000) {
  return String(value ?? "").trim().slice(0, max);
}

function normalizePhone(value) {
  return String(value ?? "")
    .replace(/[\s-]/g, "")
    .trim();
}

function ensureWallet(userId) {
  db.prepare(`
    INSERT OR IGNORE INTO wallets (user_id)
    VALUES (?)
  `).run(userId);
}

function publicUser(row) {
  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    phone: row.phone,
    role: row.role,
    bio: row.bio || "",
    skills: row.skills || "",
    avatar: row.avatar || "",
    points: row.points || 0,
    rating: row.rating ?? 5,
    createdAt: row.created_at
  };
}

function getUser(userId) {
  return db.prepare(`
    SELECT *
    FROM users
    WHERE id = ?
  `).get(userId);
}

function getWallet(userId) {
  ensureWallet(userId);

  return db.prepare(`
    SELECT *
    FROM wallets
    WHERE user_id = ?
  `).get(userId);
}

function projectView(project) {
  if (!project) return null;

  return {
    id: project.id,
    clientId: project.client_id,
    clientName: project.client_name || "",
    title: project.title,
    description: project.description,
    category: project.category || "عمومی",
    budget: project.budget,
    status: project.status,
    freelancerId: project.freelancer_id,
    freelancerName: project.freelancer_name || "",
    createdAt: project.created_at,
    updatedAt: project.updated_at
  };
}

function getProject(projectId) {
  return db.prepare(`
    SELECT
      p.*,
      c.name AS client_name,
      f.name AS freelancer_name
    FROM projects p
    JOIN users c ON c.id = p.client_id
    LEFT JOIN users f ON f.id = p.freelancer_id
    WHERE p.id = ?
  `).get(projectId);
}

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "Skillora v15",
    database: "sqlite"
  });
});

/* =========================
   AUTH
========================= */

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
        "نام، شماره موبایل معتبر، رمز حداقل ۸ کاراکتری و نقش معتبر لازم است."
    });
  }

  try {
    const result = db.prepare(`
      INSERT INTO users
        (name, phone, password_hash, role)
      VALUES
        (?, ?, ?, ?)
    `).run(
      name,
      phone,
      hashPassword(password),
      role
    );

    const user = getUser(result.lastInsertRowid);

    ensureWallet(user.id);

    setSessionCookie(
      res,
      signToken(user)
    );

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

app.post(
  "/api/auth/login",
  loginLimiter,
  (req, res) => {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    const user = db.prepare(`
      SELECT *
      FROM users
      WHERE phone = ?
    `).get(phone);

    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({
        error: "شماره موبایل یا رمز عبور اشتباه است."
      });
    }

    ensureWallet(user.id);

    setSessionCookie(
      res,
      signToken(user)
    );

    res.json({
      user: publicUser(user)
    });
  }
);

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  const user = getUser(req.user.id);

  if (!user) {
    return res.status(404).json({
      error: "کاربر پیدا نشد."
    });
  }

  ensureWallet(user.id);

  res.json({
    user: publicUser(user)
  });
});

/* =========================
   PROFILE
========================= */

app.patch("/api/me", requireAuth, (req, res) => {
  const name = cleanText(req.body.name, 80);
  const bio = cleanText(req.body.bio, 1000);
  const skills = cleanText(req.body.skills, 1000);

  if (!name) {
    return res.status(400).json({
      error: "نام نمی‌تواند خالی باشد."
    });
  }

  db.prepare(`
    UPDATE users
    SET
      name = ?,
      bio = ?,
      skills = ?
    WHERE id = ?
  `).run(
    name,
    bio,
    skills,
    req.user.id
  );

  const user = getUser(req.user.id);

  res.json({
    user: publicUser(user)
  });
});

/* =========================
   DASHBOARD
========================= */

app.get("/api/dashboard", requireAuth, (req, res) => {
  const userId = req.user.id;

  const wallet = getWallet(userId);

  const activeProjects = db.prepare(`
    SELECT COUNT(*) AS count
    FROM projects
    WHERE
      (
        client_id = ?
        OR freelancer_id = ?
      )
      AND status = 'in_progress'
  `).get(userId, userId).count;

  const recentRows = db.prepare(`
    SELECT
      p.*,
      c.name AS client_name,
      f.name AS freelancer_name
    FROM projects p
    JOIN users c ON c.id = p.client_id
    LEFT JOIN users f ON f.id = p.freelancer_id
    WHERE
      p.client_id = ?
      OR p.freelancer_id = ?
    ORDER BY p.updated_at DESC
    LIMIT 8
  `).all(userId, userId);

  const claims = db.prepare(`
    SELECT COUNT(*) AS count
    FROM reward_claims
    WHERE user_id = ?
  `).get(userId).count;

  res.json({
    stats: {
      wallet: wallet.balance,
      income: wallet.total_income,
      spent: wallet.total_spent,
      rewards: getUser(userId).points || 0,
      activeProjects
    },

    recent: recentRows.map(projectView),

    claims
  });
});

/* =========================
   PROJECTS
========================= */

app.get("/api/projects", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT
      p.*,
      c.name AS client_name,
      f.name AS freelancer_name
    FROM projects p
    JOIN users c ON c.id = p.client_id
    LEFT JOIN users f ON f.id = p.freelancer_id
    ORDER BY p.created_at DESC
  `).all();

  res.json({
    projects: rows.map(projectView)
  });
});

app.post(
  "/api/projects",
  requireAuth,
  requireRole("client"),
  (req, res) => {
    const title = cleanText(req.body.title, 120);
    const description = cleanText(req.body.description, 3000);
    const category = cleanText(
      req.body.category,
      100
    ) || "عمومی";

    const budget = Number(req.body.budget);

    if (
      !title ||
      !description ||
      !Number.isFinite(budget) ||
      budget <= 0
    ) {
      return res.status(400).json({
        error: "عنوان، توضیحات و بودجه معتبر لازم است."
      });
    }

    const result = db.prepare(`
      INSERT INTO projects
        (
          client_id,
          title,
          description,
          category,
          budget,
          status
        )
      VALUES
        (?, ?, ?, ?, ?, 'open')
    `).run(
      req.user.id,
      title,
      description,
      category,
      Math.round(budget)
    );

    const project = getProject(
      result.lastInsertRowid
    );

    res.status(201).json({
      project: projectView(project)
    });
  }
);

/* =========================
   APPLICATIONS
========================= */

app.post(
  "/api/projects/:id/apply",
  requireAuth,
  requireRole("freelancer"),
  (req, res) => {
    const projectId = Number(req.params.id);

    const project = getProject(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (project.status !== "open") {
      return res.status(400).json({
        error: "این پروژه دیگر قابل درخواست نیست."
      });
    }

    if (project.client_id === req.user.id) {
      return res.status(400).json({
        error: "نمی‌توانید برای پروژه خودتان درخواست ارسال کنید."
      });
    }

    const message = cleanText(
      req.body.message,
      1500
    );

    const proposedPrice = Number(
      req.body.proposedPrice ??
      req.body.proposed_price ??
      project.budget
    );

    if (
      !Number.isFinite(proposedPrice) ||
      proposedPrice <= 0
    ) {
      return res.status(400).json({
        error: "مبلغ پیشنهادی معتبر نیست."
      });
    }

    try {
      const result = db.prepare(`
        INSERT INTO applications
          (
            project_id,
            freelancer_id,
            message,
            proposed_price
          )
        VALUES
          (?, ?, ?, ?)
      `).run(
        projectId,
        req.user.id,
        message,
        Math.round(proposedPrice)
      );

      res.status(201).json({
        application: {
          id: result.lastInsertRowid,
          projectId,
          freelancerId: req.user.id,
          message,
          proposedPrice: Math.round(proposedPrice),
          status: "pending"
        }
      });
    } catch (err) {
      if (String(err.message).includes("UNIQUE")) {
        return res.status(409).json({
          error: "قبلاً برای این پروژه درخواست ارسال کرده‌اید."
        });
      }

      console.error(err);

      res.status(500).json({
        error: "ارسال درخواست ناموفق بود."
      });
    }
  }
);

app.get(
  "/api/projects/:id/applications",
  requireAuth,
  (req, res) => {
    const projectId = Number(req.params.id);

    const project = getProject(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (
      project.client_id !== req.user.id &&
      project.freelancer_id !== req.user.id
    ) {
      return res.status(403).json({
        error: "دسترسی ندارید."
      });
    }

    const rows = db.prepare(`
      SELECT
        a.*,
        u.name AS freelancer_name,
        u.phone AS freelancer_phone,
        u.bio AS freelancer_bio,
        u.skills AS freelancer_skills,
        u.rating AS freelancer_rating
      FROM applications a
      JOIN users u
        ON u.id = a.freelancer_id
      WHERE a.project_id = ?
      ORDER BY a.created_at DESC
    `).all(projectId);

    res.json({
      applications: rows.map(a => ({
        id: a.id,
        projectId: a.project_id,
        freelancerId: a.freelancer_id,
        freelancerName: a.freelancer_name,
        freelancerPhone: a.freelancer_phone,
        freelancerBio: a.freelancer_bio || "",
        freelancerSkills: a.freelancer_skills || "",
        freelancerRating: a.freelancer_rating ?? 5,
        message: a.message || "",
        proposedPrice: a.proposed_price,
        status: a.status,
        createdAt: a.created_at
      }))
    });
  }
);

app.post(
  "/api/projects/:id/select-freelancer",
  requireAuth,
  requireRole("client"),
  (req, res) => {
    const projectId = Number(req.params.id);
    const freelancerId = Number(
      req.body.freelancerId ??
      req.body.freelancer_id
    );

    const project = getProject(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (project.client_id !== req.user.id) {
      return res.status(403).json({
        error: "فقط صاحب پروژه می‌تواند فریلنسر را انتخاب کند."
      });
    }

    if (project.status !== "open") {
      return res.status(400).json({
        error: "این پروژه دیگر قابل انتخاب نیست."
      });
    }

    const freelancer = getUser(freelancerId);

    if (
      !freelancer ||
      freelancer.role !== "freelancer"
    ) {
      return res.status(400).json({
        error: "فریلنسر معتبر نیست."
      });
    }

    const application = db.prepare(`
      SELECT *
      FROM applications
      WHERE
        project_id = ?
        AND freelancer_id = ?
    `).get(
      projectId,
      freelancerId
    );

    if (!application) {
      return res.status(404).json({
        error: "درخواست این فریلنسر پیدا نشد."
      });
    }

    const transaction = db.transaction(() => {
      db.prepare(`
        UPDATE projects
        SET
          freelancer_id = ?,
          status = 'in_progress',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(
        freelancerId,
        projectId
      );

      db.prepare(`
        UPDATE applications
        SET status = CASE
          WHEN freelancer_id = ? THEN 'accepted'
          ELSE 'rejected'
        END
        WHERE project_id = ?
      `).run(
        freelancerId,
        projectId
      );
    });

    transaction();

    res.json({
      project: projectView(
        getProject(projectId)
      )
    });
  }
);

/* =========================
   PROJECT STATUS
========================= */

app.post(
  "/api/projects/:id/status",
  requireAuth,
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
        error: "وضعیت نامعتبر است."
      });
    }

    const project = getProject(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (
      project.client_id !== req.user.id &&
      project.freelancer_id !== req.user.id
    ) {
      return res.status(403).json({
        error: "دسترسی ندارید."
      });
    }

    db.prepare(`
      UPDATE projects
      SET
        status = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      status,
      projectId
    );

    res.json({
      project: projectView(
        getProject(projectId)
      )
    });
  }
);

/* =========================
   PROJECT PAYMENT
========================= */

app.post(
  "/api/projects/:id/pay",
  requireAuth,
  requireRole("client"),
  (req, res) => {
    const projectId = Number(req.params.id);

    const project = getProject(projectId);

    if (!project) {
      return res.status(404).json({
        error: "پروژه پیدا نشد."
      });
    }

    if (project.client_id !== req.user.id) {
      return res.status(403).json({
        error: "فقط صاحب پروژه می‌تواند پرداخت کند."
      });
    }

    if (!project.freelancer_id) {
      return res.status(400).json({
        error: "ابتدا باید یک فریلنسر انتخاب شود."
      });
    }

    if (
      project.status !== "in_progress" &&
      project.status !== "completed"
    ) {
      return res.status(400).json({
        error: "این پروژه هنوز آماده پرداخت نیست."
      });
    }

    const existingPayment = db.prepare(`
      SELECT *
      FROM project_payments
      WHERE project_id = ?
    `).get(projectId);

    if (
      existingPayment &&
      ["paid", "released"].includes(
        existingPayment.status
      )
    ) {
      return res.status(409).json({
        error: "پرداخت این پروژه قبلاً انجام شده است."
      });
    }

    const clientWallet = getWallet(req.user.id);

    const amount = Number(project.budget);

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error: "مبلغ پروژه معتبر نیست."
      });
    }

    if (clientWallet.balance < amount) {
      return res.status(400).json({
        error: "موجودی کیف پول برای پرداخت کافی نیست."
      });
    }

    const transaction = db.transaction(() => {
      db.prepare(`
        UPDATE wallets
        SET
          balance = balance - ?,
          total_spent = total_spent + ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
      `).run(
        amount,
        amount,
        req.user.id
      );

      ensureWallet(project.freelancer_id);

      db.prepare(`
        UPDATE wallets
        SET
          balance = balance + ?,
          total_income = total_income + ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
      `).run(
        amount,
        amount,
        project.freelancer_id
      );

      db.prepare(`
        INSERT INTO wallet_transactions
          (
            user_id,
            type,
            amount,
            description,
            project_id
          )
        VALUES
          (?, 'payment', ?, ?, ?)
      `).run(
        req.user.id,
        amount,
        `پرداخت پروژه: ${project.title}`,
        projectId
      );

      db.prepare(`
        INSERT INTO wallet_transactions
          (
            user_id,
            type,
            amount,
            description,
            project_id
          )
        VALUES
          (?, 'income', ?, ?, ?)
      `).run(
        project.freelancer_id,
        amount,
        `دریافت درآمد پروژه: ${project.title}`,
        projectId
      );

      if (existingPayment) {
        db.prepare(`
          UPDATE project_payments
          SET
            freelancer_id = ?,
            amount = ?,
            status = 'released',
            paid_at = CURRENT_TIMESTAMP,
            released_at = CURRENT_TIMESTAMP
          WHERE project_id = ?
        `).run(
          project.freelancer_id,
          amount,
          projectId
        );
      } else {
        db.prepare(`
          INSERT INTO project_payments
            (
              project_id,
              client_id,
              freelancer_id,
              amount,
              status,
              paid_at,
              released_at
            )
          VALUES
            (?, ?, ?, ?, 'released',
             CURRENT_TIMESTAMP,
             CURRENT_TIMESTAMP)
        `).run(
          projectId,
          req.user.id,
          project.freelancer_id,
          amount
        );
      }

      db.prepare(`
        UPDATE projects
        SET
          status = 'completed',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(projectId);
    });

    try {
      transaction();
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error: "پرداخت انجام نشد."
      });
    }

    res.json({
      ok: true,
      message: "پرداخت پروژه با موفقیت انجام شد.",
      project: projectView(
        getProject(projectId)
      ),
      wallet: getWallet(req.user.id)
    });
  }
);

/* =========================
   WALLET
========================= */

app.get("/api/wallet", requireAuth, (req, res) => {
  const wallet = getWallet(req.user.id);

  const transactions = db.prepare(`
    SELECT
      t.*,
      p.title AS project_title
    FROM wallet_transactions t
    LEFT JOIN projects p
      ON p.id = t.project_id
    WHERE t.user_id = ?
    ORDER BY t.created_at DESC
    LIMIT 100
  `).all(req.user.id);

  res.json({
    wallet: {
      balance: wallet.balance,
      totalIncome: wallet.total_income,
      totalSpent: wallet.total_spent
    },

    transactions: transactions.map(t => ({
      id: t.id,
      type: t.type,
      amount: t.amount,
      description: t.description || "",
      projectId: t.project_id,
      projectTitle: t.project_title || "",
      createdAt: t.created_at
    }))
  });
});

app.post(
  "/api/wallet/demo-deposit",
  requireAuth,
  (req, res) => {
    const amount = Number(req.body.amount);

    if (
      !Number.isFinite(amount) ||
      amount <= 0 ||
      amount > 1000000000
    ) {
      return res.status(400).json({
        error: "مبلغ شارژ نامعتبر است."
      });
    }

    ensureWallet(req.user.id);

    const transaction = db.transaction(() => {
      db.prepare(`
        UPDATE wallets
        SET
          balance = balance + ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
      `).run(
        Math.round(amount),
        req.user.id
      );

      db.prepare(`
        INSERT INTO wallet_transactions
          (
            user_id,
            type,
            amount,
            description
          )
        VALUES
          (?, 'deposit', ?, ?)
      `).run(
        req.user.id,
        Math.round(amount),
        "شارژ آزمایشی کیف پول"
      );
    });

    transaction();

    res.json({
      ok: true,
      wallet: getWallet(req.user.id)
    });
  }
);

app.post(
  "/api/wallet/withdraw",
  requireAuth,
  (req, res) => {
    const amount = Number(req.body.amount);

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error: "مبلغ برداشت نامعتبر است."
      });
    }

    const wallet = getWallet(req.user.id);

    if (wallet.balance < amount) {
      return res.status(400).json({
        error: "موجودی کافی نیست."
      });
    }

    const transaction = db.transaction(() => {
      db.prepare(`
        UPDATE wallets
        SET
          balance = balance - ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
      `).run(
        Math.round(amount),
        req.user.id
      );

      db.prepare(`
        INSERT INTO wallet_transactions
          (
            user_id,
            type,
            amount,
            description
          )
        VALUES
          (?, 'withdraw', ?, ?)
      `).run(
        req.user.id,
        Math.round(amount),
        "برداشت از کیف پول"
      );
    });

    transaction();

    res.json({
      ok: true,
      wallet: getWallet(req.user.id)
    });
  }
);

/* =========================
   REWARDS
========================= */

const REWARDS = [
  {
    key: "profile",
    title: "تکمیل پروفایل",
    description: "نام، معرفی و مهارت‌ها را تکمیل کنید.",
    points: 100
  },
  {
    key: "first_project",
    title: "اولین پروژه",
    description: "اولین پروژه خود را ثبت کنید.",
    points: 150
  },
  {
    key: "first_application",
    title: "اولین درخواست همکاری",
    description: "برای اولین پروژه درخواست ارسال کنید.",
    points: 100
  }
];

app.get("/api/rewards", requireAuth, (req, res) => {
  const user = getUser(req.user.id);

  const claims = db.prepare(`
    SELECT reward_key
    FROM reward_claims
    WHERE user_id = ?
  `).all(req.user.id);

  const claimed = new Set(
    claims.map(x => x.reward_key)
  );

  res.json({
    points: user.points || 0,

    rewards: REWARDS.map(r => ({
      ...r,
      claimed: claimed.has(r.key)
    }))
  });
});

app.post(
  "/api/rewards/claim",
  requireAuth,
  (req, res) => {
    const rewardKey = cleanText(
      req.body.rewardKey ??
      req.body.key,
      100
    );

    const reward = REWARDS.find(
      r => r.key === rewardKey
    );

    if (!reward) {
      return res.status(404).json({
        error: "پاداش پیدا نشد."
      });
    }

    const user = getUser(req.user.id);

    let eligible = false;

    if (reward.key === "profile") {
      eligible =
        Boolean(user.name) &&
        Boolean(user.bio) &&
        Boolean(user.skills);
    }

    if (reward.key === "first_project") {
      const row = db.prepare(`
        SELECT COUNT(*) AS count
        FROM projects
        WHERE client_id = ?
      `).get(req.user.id);

      eligible = row.count > 0;
    }

    if (reward.key === "first_application") {
      const row = db.prepare(`
        SELECT COUNT(*) AS count
        FROM applications
        WHERE freelancer_id = ?
      `).get(req.user.id);

      eligible = row.count > 0;
    }

    if (!eligible) {
      return res.status(400).json({
        error: "شرایط دریافت این پاداش هنوز کامل نشده است."
      });
    }

    try {
      const transaction = db.transaction(() => {
        db.prepare(`
          INSERT INTO reward_claims
            (
              user_id,
              reward_key,
              points
            )
          VALUES
            (?, ?, ?)
        `).run(
          req.user.id,
          reward.key,
          reward.points
        );

        db.prepare(`
          UPDATE users
          SET points = points + ?
          WHERE id = ?
        `).run(
          reward.points,
          req.user.id
        );

        ensureWallet(req.user.id);

        db.prepare(`
          INSERT INTO wallet_transactions
            (
              user_id,
              type,
              amount,
              description
            )
          VALUES
            (?, 'reward', ?, ?)
        `).run(
          req.user.id,
          reward.points,
          `دریافت پاداش: ${reward.title}`
        );
      });

      transaction();
    } catch (err) {
      if (String(err.message).includes("UNIQUE")) {
        return res.status(409).json({
          error: "این پاداش قبلاً دریافت شده است."
        });
      }

      throw err;
    }

    res.json({
      ok: true,
      points: getUser(req.user.id).points
    });
  }
);

/* =========================
   STATIC FRONTEND
========================= */

app.use(
  express.static(frontend, {
    extensions: ["html"]
  })
);

app.get("*", (req, res) => {
  if (
    req.path.startsWith("/api/")
  ) {
    return res.status(404).json({
      error: "API endpoint not found."
    });
  }

  res.sendFile(
    path.join(frontend, "index.html")
  );
});

/* =========================
   ERROR HANDLER
========================= */

app.use((err, _req, res, _next) => {
  console.error(err);

  if (res.headersSent) {
    return;
  }

  res.status(500).json({
    error: "خطای داخلی سرور."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Skillora v15 running on port ${PORT}`
  );
});
