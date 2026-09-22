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

const DEFAULT_COMMISSION = Math.min(
  50,
  Math.max(0, Number(process.env.SKILLORA_COMMISSION || 5))
);

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

const adminOnly = requireRole("admin");

/* =========================
   HELPERS
========================= */

function cleanText(value, max = 1000) {
  return String(value ?? "").trim().slice(0, max);
}

function normalizePhone(value) {
  return String(value ?? "")
    .replace(/[\s-]/g, "")
    .trim();
}

function getUser(id) {
  return db
    .prepare("SELECT * FROM users WHERE id = ?")
    .get(id);
}

function ensureWallet(userId) {
  db.prepare(`
    INSERT OR IGNORE INTO wallets (user_id)
    VALUES (?)
  `).run(userId);
}

function getWallet(userId) {
  ensureWallet(userId);

  return db
    .prepare("SELECT * FROM wallets WHERE user_id = ?")
    .get(userId);
}

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    role: user.role,
    bio: user.bio || "",
    skills: user.skills || "",
    avatar: user.avatar || "",
    points: user.points || 0,
    rating: user.rating ?? 5,
    createdAt: user.created_at
  };
}

function getProject(id) {
  return db.prepare(`
    SELECT
      p.*,
      c.name AS client_name,
      f.name AS freelancer_name
    FROM projects p
    JOIN users c
      ON c.id = p.client_id
    LEFT JOIN users f
      ON f.id = p.freelancer_id
    WHERE p.id = ?
  `).get(id);
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

function getSettings() {
  return db
    .prepare(`
      SELECT commission_rate
      FROM platform_settings
      WHERE id = 1
    `)
    .get();
}

function commissionRate() {
  const row = getSettings();

  return Number(
    row?.commission_rate ?? DEFAULT_COMMISSION
  );
}

/* =========================
   DATABASE MIGRATION
========================= */

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS platform_settings (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      commission_rate REAL NOT NULL DEFAULT ${DEFAULT_COMMISSION},
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    INSERT OR IGNORE INTO platform_settings
      (id, commission_rate)
    VALUES
      (1, ${DEFAULT_COMMISSION});

    CREATE TABLE IF NOT EXISTS platform_ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER UNIQUE,
      gross_amount INTEGER NOT NULL,
      commission_rate REAL NOT NULL,
      commission_amount INTEGER NOT NULL,
      freelancer_net INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(project_id)
        REFERENCES projects(id)
        ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_platform_ledger_project
    ON platform_ledger(project_id);
  `);

  const columns = db
    .prepare("PRAGMA table_info(project_payments)")
    .all()
    .map(column => column.name);

  if (!columns.includes("commission_rate")) {
    db.exec(`
      ALTER TABLE project_payments
      ADD COLUMN commission_rate REAL NOT NULL DEFAULT 0
    `);
  }

  if (!columns.includes("commission_amount")) {
    db.exec(`
      ALTER TABLE project_payments
      ADD COLUMN commission_amount INTEGER NOT NULL DEFAULT 0
    `);
  }

  if (!columns.includes("freelancer_net")) {
    db.exec(`
      ALTER TABLE project_payments
      ADD COLUMN freelancer_net INTEGER NOT NULL DEFAULT 0
    `);
  }
}

/* =========================
   ADMIN SETUP
========================= */

function ensureAdminFromEnv() {
  const phone = normalizePhone(
    process.env.SKILLORA_ADMIN_PHONE
  );

  const password = String(
    process.env.SKILLORA_ADMIN_PASSWORD || ""
  );

  const name = cleanText(
    process.env.SKILLORA_ADMIN_NAME ||
      "Skillora Owner",
    80
  );

  if (!phone || password.length < 8) {
    return;
  }

  const existing = db
    .prepare("SELECT * FROM users WHERE phone = ?")
    .get(phone);

  if (!existing) {
    const result = db.prepare(`
      INSERT INTO users
        (name, phone, password_hash, role)
      VALUES
        (?, ?, ?, 'admin')
    `).run(
      name,
      phone,
      hashPassword(password)
    );

    ensureWallet(result.lastInsertRowid);

    return;
  }

  if (existing.role !== "admin") {
    db.prepare(`
      UPDATE users
      SET role = 'admin',
          name = ?
      WHERE id = ?
    `).run(
      name,
      existing.id
    );
  }

  ensureWallet(existing.id);
}

migrate();
ensureAdminFromEnv();

/* =========================
   HEALTH
========================= */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "Skillora v15 Plus",
    database: "sqlite",
    commissionRate: commissionRate()
  });
});

/* =========================
   AUTH
========================= */

app.post(
  "/api/auth/register",
  (req, res) => {
    const name = cleanText(req.body.name, 80);
    const phone = normalizePhone(req.body.phone);
    const password = String(
      req.body.password || ""
    );

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

      const user = getUser(
        result.lastInsertRowid
      );

      ensureWallet(user.id);

      setSessionCookie(
        res,
        signToken(user)
      );

      res.status(201).json({
        user: publicUser(user)
      });
    } catch (error) {
      if (
        String(error.message).includes("UNIQUE")
      ) {
        return res.status(409).json({
          error:
            "این شماره موبایل قبلاً ثبت شده است."
        });
      }

      console.error(error);

      res.status(500).json({
        error: "خطای داخلی سرور."
      });
    }
  }
);

app.post(
  "/api/auth/login",
  loginLimiter,
  (req, res) => {
    const phone = normalizePhone(
      req.body.phone
    );

    const password = String(
      req.body.password || ""
    );

    const user = db
      .prepare(`
        SELECT *
        FROM users
        WHERE phone = ?
      `)
      .get(phone);

    if (
      !user ||
      !verifyPassword(
        password,
        user.password_hash
      )
    ) {
      return res.status(401).json({
        error:
          "شماره موبایل یا رمز عبور اشتباه است."
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

app.post(
  "/api/auth/logout",
  (_req, res) => {
    res.clearCookie(COOKIE_NAME);

    res.json({
      ok: true
    });
  }
);

app.get(
  "/api/me",
  requireAuth,
  (req, res) => {
    const user = getUser(
      req.auth.sub
    );

    if (!user) {
      return res.status(404).json({
        error: "کاربر پیدا نشد."
      });
    }

    ensureWallet(user.id);

    res.json({
      user: publicUser(user)
    });
  }
);

/* =========================
   PROFILE
========================= */

app.patch(
  "/api/me",
  requireAuth,
  (req, res) => {
    const name = cleanText(
      req.body.name,
      80
    );

    const bio = cleanText(
      req.body.bio,
      1000
    );

    const skills = cleanText(
      req.body.skills,
      1000
    );

    if (!name) {
      return res.status(400).json({
        error:
          "نام نمی‌تواند خالی باشد."
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
      req.auth.sub
    );

    res.json({
      user: publicUser(
        getUser(req.auth.sub)
      )
    });
  }
);

/* =========================
   DASHBOARD
========================= */

app.get(
  "/api/dashboard",
  requireAuth,
  (req, res) => {
    const userId = req.auth.sub;

    const wallet = getWallet(userId);

    const activeProjects = db
      .prepare(`
        SELECT COUNT(*) AS count
        FROM projects
        WHERE
          (
            client_id = ?
            OR freelancer_id = ?
          )
          AND status = 'in_progress'
      `)
      .get(
        userId,
        userId
      ).count;

    const recent = db
      .prepare(`
        SELECT
          p.*,
          c.name AS client_name,
          f.name AS freelancer_name
        FROM projects p
        JOIN users c
          ON c.id = p.client_id
        LEFT JOIN users f
          ON f.id = p.freelancer_id
        WHERE
          p.client_id = ?
          OR p.freelancer_id = ?
        ORDER BY p.updated_at DESC
        LIMIT 8
      `)
      .all(
        userId,
        userId
      );

    const claims = db
      .prepare(`
        SELECT COUNT(*) AS count
        FROM reward_claims
        WHERE user_id = ?
      `)
      .get(userId).count;

    res.json({
      stats: {
        wallet: wallet.balance,
        income: wallet.total_income,
        spent: wallet.total_spent,
        rewards:
          getUser(userId).points || 0,
        activeProjects
      },

      recent: recent.map(projectView),

      claims
    });
  }
);

/* =========================
   PROJECTS
========================= */

app.get(
  "/api/projects",
  requireAuth,
  (_req, res) => {
    const rows = db.prepare(`
      SELECT
        p.*,
        c.name AS client_name,
        f.name AS freelancer_name
      FROM projects p
      JOIN users c
        ON c.id = p.client_id
      LEFT JOIN users f
        ON f.id = p.freelancer_id
      ORDER BY p.created_at DESC
    `).all();

    res.json({
      projects: rows.map(projectView)
    });
  }
);

app.post(
  "/api/projects",
  requireAuth,
  requireRole("client"),
  (req, res) => {
    const title = cleanText(
      req.body.title,
      120
    );

    const description = cleanText(
      req.body.description,
      3000
    );

    const category =
      cleanText(
        req.body.category,
        100
      ) || "عمومی";

    const budget = Number(
      req.body.budget
    );

    if (
      !title ||
      !description ||
      !Number.isFinite(budget) ||
      budget <= 0
    ) {
      return res.status(400).json({
        error:
          "عنوان، توضیحات و بودجه معتبر لازم است."
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
      req.auth.sub,
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
    const projectId = Number(
      req.params.id
    );

    const project = getProject(
      projectId
    );

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    if (project.status !== "open") {
      return res.status(400).json({
        error:
          "این پروژه دیگر قابل درخواست نیست."
      });
    }

    if (
      project.client_id === req.auth.sub
    ) {
      return res.status(400).json({
        error:
          "نمی‌توانید برای پروژه خودتان درخواست ارسال کنید."
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
        error:
          "مبلغ پیشنهادی معتبر نیست."
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
        req.auth.sub,
        message,
        Math.round(proposedPrice)
      );

      res.status(201).json({
        application: {
          id: result.lastInsertRowid,
          projectId,
          freelancerId: req.auth.sub,
          message,
          proposedPrice:
            Math.round(proposedPrice),
          status: "pending"
        }
      });
    } catch (error) {
      if (
        String(error.message).includes(
          "UNIQUE"
        )
      ) {
        return res.status(409).json({
          error:
            "قبلاً برای این پروژه درخواست ارسال کرده‌اید."
        });
      }

      console.error(error);

      res.status(500).json({
        error:
          "ارسال درخواست ناموفق بود."
      });
    }
  }
);

app.get(
  "/api/projects/:id/applications",
  requireAuth,
  (req, res) => {
    const projectId = Number(
      req.params.id
    );

    const project = getProject(
      projectId
    );

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    if (
      project.client_id !== req.auth.sub &&
      project.freelancer_id !== req.auth.sub
    ) {
      return res.status(403).json({
        error:
          "دسترسی ندارید."
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
        freelancerId:
          a.freelancer_id,
        freelancerName:
          a.freelancer_name,
        freelancerPhone:
          a.freelancer_phone,
        freelancerBio:
          a.freelancer_bio || "",
        freelancerSkills:
          a.freelancer_skills || "",
        freelancerRating:
          a.freelancer_rating ?? 5,
        message: a.message || "",
        proposedPrice:
          a.proposed_price,
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
    const projectId = Number(
      req.params.id
    );

    const freelancerId = Number(
      req.body.freelancerId ??
      req.body.freelancer_id
    );

    const project = getProject(
      projectId
    );

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    if (
      project.client_id !== req.auth.sub
    ) {
      return res.status(403).json({
        error:
          "فقط صاحب پروژه می‌تواند فریلنسر را انتخاب کند."
      });
    }

    if (project.status !== "open") {
      return res.status(400).json({
        error:
          "این پروژه دیگر قابل انتخاب نیست."
      });
    }

    const freelancer = getUser(
      freelancerId
    );

    if (
      !freelancer ||
      freelancer.role !== "freelancer"
    ) {
      return res.status(400).json({
        error:
          "فریلنسر معتبر نیست."
      });
    }

    const application = db
      .prepare(`
        SELECT *
        FROM applications
        WHERE
          project_id = ?
          AND freelancer_id = ?
      `)
      .get(
        projectId,
        freelancerId
      );

    if (!application) {
      return res.status(404).json({
        error:
          "درخواست این فریلنسر پیدا نشد."
      });
    }

    const transaction =
      db.transaction(() => {
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
          SET status =
            CASE
              WHEN freelancer_id = ?
              THEN 'accepted'
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
    const projectId = Number(
      req.params.id
    );

    const status = cleanText(
      req.body.status,
      30
    );

    const allowed = [
      "open",
      "in_progress",
      "completed",
      "cancelled"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error:
          "وضعیت نامعتبر است."
      });
    }

    const project = getProject(
      projectId
    );

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    if (
      project.client_id !== req.auth.sub &&
      project.freelancer_id !== req.auth.sub
    ) {
      return res.status(403).json({
        error:
          "دسترسی ندارید."
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
    const projectId = Number(
      req.params.id
    );

    const project = getProject(
      projectId
    );

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    if (
      project.client_id !== req.auth.sub
    ) {
      return res.status(403).json({
        error:
          "فقط صاحب پروژه می‌تواند پرداخت کند."
      });
    }

    if (!project.freelancer_id) {
      return res.status(400).json({
        error:
          "ابتدا باید یک فریلنسر انتخاب شود."
      });
    }

    if (
      project.status !== "in_progress" &&
      project.status !== "completed"
    ) {
      return res.status(400).json({
        error:
          "این پروژه هنوز آماده پرداخت نیست."
      });
    }

    const existingPayment = db
      .prepare(`
        SELECT *
        FROM project_payments
        WHERE project_id = ?
      `)
      .get(projectId);

    if (
      existingPayment &&
      ["paid", "released"].includes(
        existingPayment.status
      )
    ) {
      return res.status(409).json({
        error:
          "پرداخت این پروژه قبلاً انجام شده است."
      });
    }

    const clientWallet =
      getWallet(req.auth.sub);

    const amount = Number(
      project.budget
    );

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error:
          "مبلغ پروژه معتبر نیست."
      });
    }

    if (
      clientWallet.balance < amount
    ) {
      return res.status(400).json({
        error:
          "موجودی کیف پول برای پرداخت کافی نیست."
      });
    }

    const rate = commissionRate();

    const commissionAmount =
      Math.round(
        amount * rate / 100
      );

    const freelancerNet =
      amount - commissionAmount;

    const admin = db
      .prepare(`
        SELECT *
        FROM users
        WHERE role = 'admin'
        ORDER BY id ASC
        LIMIT 1
      `)
      .get();

    if (!admin) {
      return res.status(500).json({
        error:
          "حساب مدیریت Skillora هنوز ساخته نشده است."
      });
    }

    const transaction =
      db.transaction(() => {
        /* client */

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
          req.auth.sub
        );

        /* freelancer */

        ensureWallet(
          project.freelancer_id
        );

        db.prepare(`
          UPDATE wallets
          SET
            balance = balance + ?,
            total_income = total_income + ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE user_id = ?
        `).run(
          freelancerNet,
          freelancerNet,
          project.freelancer_id
        );

        /* admin commission */

        ensureWallet(admin.id);

        db.prepare(`
          UPDATE wallets
          SET
            balance = balance + ?,
            total_income = total_income + ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE user_id = ?
        `).run(
          commissionAmount,
          commissionAmount,
          admin.id
        );

        /* client transaction */

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
          req.auth.sub,
          amount,
          `پرداخت پروژه: ${project.title}`,
          projectId
        );

        /* freelancer transaction */

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
          freelancerNet,
          `دریافت درآمد پروژه: ${project.title}`,
          projectId
        );

        /* admin transaction */

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
          admin.id,
          commissionAmount,
          `کمیسیون Skillora از پروژه: ${project.title}`,
          projectId
        );

        /* payment record */

        if (existingPayment) {
          db.prepare(`
            UPDATE project_payments
            SET
              freelancer_id = ?,
              amount = ?,
              commission_rate = ?,
              commission_amount = ?,
              freelancer_net = ?,
              status = 'released',
              paid_at = CURRENT_TIMESTAMP,
              released_at = CURRENT_TIMESTAMP
            WHERE project_id = ?
          `).run(
            project.freelancer_id,
            amount,
            rate,
            commissionAmount,
            freelancerNet,
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
                commission_rate,
                commission_amount,
                freelancer_net,
                status,
                paid_at,
                released_at
              )
            VALUES
              (?, ?, ?, ?, ?, ?, ?, 'released',
               CURRENT_TIMESTAMP,
               CURRENT_TIMESTAMP)
          `).run(
            projectId,
            req.auth.sub,
            project.freelancer_id,
            amount,
            rate,
            commissionAmount,
            freelancerNet
          );
        }

        /* platform ledger */

        db.prepare(`
          INSERT OR REPLACE INTO platform_ledger
            (
              project_id,
              gross_amount,
              commission_rate,
              commission_amount,
              freelancer_net
            )
          VALUES
            (?, ?, ?, ?, ?)
        `).run(
          projectId,
          amount,
          rate,
          commissionAmount,
          freelancerNet
        );

        /* project complete */

        db.prepare(`
          UPDATE projects
          SET
            status = 'completed',
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(projectId);

        /* reward freelancer */

        db.prepare(`
          UPDATE users
          SET points = points + ?
          WHERE id = ?
        `).run(
          Math.max(
            1,
            Math.floor(
              freelancerNet / 100000
            )
          ),
          project.freelancer_id
        );
      });

    transaction();

    res.json({
      ok: true,
      payment: {
        grossAmount: amount,
        commissionRate: rate,
        commissionAmount,
        freelancerNet
      },
      project: projectView(
        getProject(projectId)
      )
    });
  }
);

/* =========================
   WALLET
========================= */

app.get(
  "/api/wallet",
  requireAuth,
  (req, res) => {
    const wallet = getWallet(
      req.auth.sub
    );

    const transactions = db
      .prepare(`
        SELECT *
        FROM wallet_transactions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 50
      `)
      .all(req.auth.sub);

    res.json({
      wallet,
      transactions
    });
  }
);

/*
  DEMO DEPOSIT
  فقط برای تست سیستم.
  در نسخه واقعی باید به درگاه پرداخت متصل شود.
*/

app.post(
  "/api/wallet/demo-deposit",
  requireAuth,
  (req, res) => {
    const amount = Math.round(
      Number(req.body.amount)
    );

    if (
      !Number.isFinite(amount) ||
      amount <= 0 ||
      amount > 1000000000
    ) {
      return res.status(400).json({
        error:
          "مبلغ شارژ آزمایشی معتبر نیست."
      });
    }

    const transaction =
      db.transaction(() => {
        ensureWallet(
          req.auth.sub
        );

        db.prepare(`
          UPDATE wallets
          SET
            balance = balance + ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE user_id = ?
        `).run(
          amount,
          req.auth.sub
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
          req.auth.sub,
          amount,
          "شارژ آزمایشی کیف پول"
        );
      });

    transaction();

    res.json({
      ok: true,
      wallet: getWallet(
        req.auth.sub
      )
    });
  }
);

/* =========================
   WITHDRAW
========================= */

app.post(
  "/api/wallet/withdraw",
  requireAuth,
  (req, res) => {
    const amount = Math.round(
      Number(req.body.amount)
    );

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error:
          "مبلغ برداشت معتبر نیست."
      });
    }

    const wallet = getWallet(
      req.auth.sub
    );

    if (wallet.balance < amount) {
      return res.status(400).json({
        error:
          "موجودی کیف پول کافی نیست."
      });
    }

    const transaction =
      db.transaction(() => {
        db.prepare(`
          UPDATE wallets
          SET
            balance = balance - ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE user_id = ?
        `).run(
          amount,
          req.auth.sub
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
          req.auth.sub,
          amount,
          "برداشت از کیف پول"
        );
      });

    transaction();

    res.json({
      ok: true,
      wallet: getWallet(
        req.auth.sub
      )
    });
  }
);

/* =========================
   REWARDS
========================= */

app.get(
  "/api/rewards",
  requireAuth,
  (req, res) => {
    const user = getUser(
      req.auth.sub
    );

    const claims = db
      .prepare(`
        SELECT *
        FROM reward_claims
        WHERE user_id = ?
        ORDER BY created_at DESC
      `)
      .all(req.auth.sub);

    res.json({
      points: user.points || 0,
      claims
    });
  }
);

app.post(
  "/api/rewards/claim",
  requireAuth,
  (req, res) => {
    const rewardKey = cleanText(
      req.body.rewardKey,
      80
    );

    const rewards = {
      starter: {
        points: 50,
        title: "پاداش شروع"
      },
      active: {
        points: 100,
        title: "پاداش فعالیت"
      },
      pro: {
        points: 250,
        title: "پاداش حرفه‌ای"
      }
    };

    const reward =
      rewards[rewardKey];

    if (!reward) {
      return res.status(400).json({
        error:
          "پاداش نامعتبر است."
      });
    }

    const exists = db
      .prepare(`
        SELECT id
        FROM reward_claims
        WHERE
          user_id = ?
          AND reward_key = ?
      `)
      .get(
        req.auth.sub,
        rewardKey
      );

    if (exists) {
      return res.status(409).json({
        error:
          "این پاداش قبلاً دریافت شده است."
      });
    }

    const transaction =
      db.transaction(() => {
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
          req.auth.sub,
          rewardKey,
          reward.points
        );

        db.prepare(`
          UPDATE users
          SET points = points + ?
          WHERE id = ?
        `).run(
          reward.points,
          req.auth.sub
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
            (?, 'reward', ?, ?)
        `).run(
          req.auth.sub,
          reward.points,
          `دریافت ${reward.title}`
        );
      });

    transaction();

    res.json({
      ok: true,
      points:
        getUser(req.auth.sub).points
    });
  }
);

/* =========================
   ADMIN OVERVIEW
========================= */

app.get(
  "/api/admin/overview",
  requireAuth,
  adminOnly,
  (_req, res) => {
    const users = db
      .prepare(`
        SELECT COUNT(*) count
        FROM users
        WHERE role != 'admin'
      `)
      .get().count;

    const projects = db
      .prepare(`
        SELECT COUNT(*) count
        FROM projects
      `)
      .get().count;

    const completedProjects = db
      .prepare(`
        SELECT COUNT(*) count
        FROM projects
        WHERE status = 'completed'
      `)
      .get().count;

    const gross = db
      .prepare(`
        SELECT
          COALESCE(
            SUM(gross_amount),
            0
          ) total
        FROM platform_ledger
      `)
      .get().total;

    const commission = db
      .prepare(`
        SELECT
          COALESCE(
            SUM(commission_amount),
            0
          ) total
        FROM platform_ledger
      `)
      .get().total;

    const freelancerPaid = db
      .prepare(`
        SELECT
          COALESCE(
            SUM(freelancer_net),
            0
          ) total
        FROM platform_ledger
      `)
      .get().total;

    const admin = db
      .prepare(`
        SELECT
          u.id,
          u.name,
          u.phone,
          w.balance,
          w.total_income
        FROM users u
        LEFT JOIN wallets w
          ON w.user_id = u.id
        WHERE u.role = 'admin'
        ORDER BY u.id ASC
        LIMIT 1
      `)
      .get();

    res.json({
      commissionRate:
        commissionRate(),

      stats: {
        users,
        projects,
        completedProjects,
        gross,
        commission,
        freelancerPaid
      },

      admin: admin || null
    });
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  requireAuth,
  adminOnly,
  (_req, res) => {
    const users = db.prepare(`
      SELECT
        u.id,
        u.name,
        u.phone,
        u.role,
        u.points,
        u.rating,
        u.created_at,
        COALESCE(w.balance, 0) balance,
        COALESCE(w.total_income, 0) total_income,
        COALESCE(w.total_spent, 0) total_spent
      FROM users u
      LEFT JOIN wallets w
        ON w.user_id = u.id
      ORDER BY u.created_at DESC
    `).all();

    res.json({
      users
    });
  }
);

/* =========================
   ADMIN PROJECTS
========================= */

app.get(
  "/api/admin/projects",
  requireAuth,
  adminOnly,
  (_req, res) => {
    const projects = db.prepare(`
      SELECT
        p.*,
        c.name AS client_name,
        f.name AS freelancer_name
      FROM projects p
      JOIN users c
        ON c.id = p.client_id
      LEFT JOIN users f
        ON f.id = p.freelancer_id
      ORDER BY p.created_at DESC
    `).all();

    res.json({
      projects: projects.map(
        projectView
      )
    });
  }
);

/* =========================
   ADMIN LEDGER
========================= */

app.get(
  "/api/admin/ledger",
  requireAuth,
  adminOnly,
  (_req, res) => {
    const rows = db.prepare(`
      SELECT
        l.*,
        p.title AS project_title,
        c.name AS client_name,
        f.name AS freelancer_name
      FROM platform_ledger l
      LEFT JOIN projects p
        ON p.id = l.project_id
      LEFT JOIN users c
        ON c.id = p.client_id
      LEFT JOIN users f
        ON f.id = p.freelancer_id
      ORDER BY l.created_at DESC
      LIMIT 200
    `).all();

    res.json({
      ledger: rows
    });
  }
);

/* =========================
   ADMIN SETTINGS
========================= */

app.get(
  "/api/admin/settings",
  requireAuth,
  adminOnly,
  (_req, res) => {
    res.json({
      commissionRate:
        commissionRate()
    });
  }
);

app.patch(
  "/api/admin/settings",
  requireAuth,
  adminOnly,
  (req, res) => {
    const rate = Number(
      req.body.commissionRate ??
      req.body.commission_rate
    );

    if (
      !Number.isFinite(rate) ||
      rate < 0 ||
      rate > 50
    ) {
      return res.status(400).json({
        error:
          "کمیسیون باید بین صفر تا ۵۰ درصد باشد."
      });
    }

    db.prepare(`
      UPDATE platform_settings
      SET
        commission_rate = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = 1
    `).run(rate);

    res.json({
      ok: true,
      commissionRate:
        commissionRate()
    });
  }
);

/* =========================
   PUBLIC FRONTEND
========================= */

app.use(
  express.static(frontend)
);

/*
  SPA fallback:
  هر مسیر غیر API به index.html
  هدایت می‌شود.
*/

app.get(
  "*",
  (req, res, next) => {
    if (
      req.path.startsWith("/api/")
    ) {
      return next();
    }

    res.sendFile(
      path.join(
        frontend,
        "index.html"
      )
    );
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (err, _req, res, _next) => {
    console.error(err);

    if (res.headersSent) {
      return;
    }

    res.status(500).json({
      error:
        "خطای داخلی سرور."
    });
  }
);

/* =========================
   START
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Skillora v15 Plus running at http://localhost:${PORT}`
    );
  }
);
