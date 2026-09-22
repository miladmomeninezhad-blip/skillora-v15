const path = require("path");
const express = require("express");
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
const FRONTEND_DIR = path.resolve(__dirname, "../../frontend");

const DEFAULT_COMMISSION = Math.min(
  50,
  Math.max(
    0,
    Number(process.env.SKILLORA_COMMISSION || 5)
  )
);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

function cleanText(value, max = 1000) {
  return String(value ?? "")
    .trim()
    .slice(0, max);
}

function normalizePhone(value) {
  return String(value ?? "")
    .replace(/[\s-]/g, "")
    .trim();
}

function parseMoney(value) {
  const amount = Number(value);

  if (!Number.isFinite(amount)) {
    return 0;
  }

  return Math.max(0, Math.round(amount));
}

function ensureWallet(userId) {
  db.prepare(`
    INSERT OR IGNORE INTO wallets
      (user_id, balance, total_income, total_spent)
    VALUES
      (?, 0, 0, 0)
  `).run(userId);
}

function getUser(userId) {
  return db
    .prepare(`
      SELECT *
      FROM users
      WHERE id = ?
    `)
    .get(userId);
}

function publicUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    role: user.role,
    bio: user.bio || "",
    skills: user.skills || "",
    avatar: user.avatar || "",
    points: Number(user.points || 0),
    rating: Number(user.rating || 5),
    created_at: user.created_at
  };
}

function getWallet(userId) {
  ensureWallet(userId);

  return db
    .prepare(`
      SELECT *
      FROM wallets
      WHERE user_id = ?
    `)
    .get(userId);
}

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


/* =========================================================
   ADMIN
========================================================= */

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
    return null;
  }

  let existing = db
    .prepare(`
      SELECT *
      FROM users
      WHERE phone = ?
    `)
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

    return db
      .prepare(`
        SELECT *
        FROM users
        WHERE id = ?
      `)
      .get(result.lastInsertRowid);
  }

  db.prepare(`
    UPDATE users
    SET
      name = ?,
      role = 'admin'
    WHERE id = ?
  `).run(
    name,
    existing.id
  );

  if (
    !verifyPassword(
      password,
      existing.password_hash
    )
  ) {
    db.prepare(`
      UPDATE users
      SET password_hash = ?
      WHERE id = ?
    `).run(
      hashPassword(password),
      existing.id
    );
  }

  ensureWallet(existing.id);

  return db
    .prepare(`
      SELECT *
      FROM users
      WHERE id = ?
    `)
    .get(existing.id);
}


/* =========================================================
   AUTH
========================================================= */

app.post(
  "/api/auth/register",
  (req, res) => {
    try {
      const name = cleanText(
        req.body.name,
        80
      );

      const phone = normalizePhone(
        req.body.phone
      );

      const password = String(
        req.body.password || ""
      );

      const role =
        req.body.role === "client"
          ? "client"
          : "freelancer";

      if (!name) {
        return res.status(400).json({
          error: "نام را وارد کنید."
        });
      }

      if (!phone) {
        return res.status(400).json({
          error: "شماره موبایل را وارد کنید."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "رمز عبور باید حداقل ۸ کاراکتر باشد."
        });
      }

      const exists = db
        .prepare(`
          SELECT id
          FROM users
          WHERE phone = ?
        `)
        .get(phone);

      if (exists) {
        return res.status(409).json({
          error:
            "این شماره موبایل قبلاً ثبت شده است."
        });
      }

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

      ensureWallet(result.lastInsertRowid);

      const user = getUser(
        result.lastInsertRowid
      );

      setSessionCookie(
        res,
        signToken(user)
      );

      res.json({
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error:
          "ثبت‌نام انجام نشد."
      });
    }
  }
);


app.post(
  "/api/auth/login",
  loginLimiter,
  (req, res) => {
    try {
      const phone = normalizePhone(
        req.body.phone
      );

      const password = String(
        req.body.password || ""
      );

      const adminPhone = normalizePhone(
        process.env.SKILLORA_ADMIN_PHONE
      );

      const adminPassword = String(
        process.env.SKILLORA_ADMIN_PASSWORD || ""
      );

      const isConfiguredAdmin =
        adminPhone &&
        adminPassword.length >= 8 &&
        phone === adminPhone &&
        password === adminPassword;

      if (isConfiguredAdmin) {
        const admin =
          ensureAdminFromEnv();

        if (!admin) {
          return res.status(500).json({
            error:
              "حساب مدیریت Skillora هنوز تنظیم نشده است."
          });
        }

        ensureWallet(admin.id);

        setSessionCookie(
          res,
          signToken(admin)
        );

        return res.json({
          user: publicUser(admin)
        });
      }

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
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error:
          "ورود انجام نشد."
      });
    }
  }
);


app.post(
  "/api/auth/logout",
  (_req, res) => {
    res.clearCookie(
      COOKIE_NAME,
      {
        httpOnly: true,
        sameSite: "lax",
        secure:
          process.env.NODE_ENV === "production",
        path: "/"
      }
    );

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
        error:
          "کاربر پیدا نشد."
      });
    }

    ensureWallet(user.id);

    res.json({
      user: publicUser(user)
    });
  }
);


/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  (_req, res) => {
    res.json({
      ok: true,
      service: "Skillora v15 Plus",
      database: "sqlite"
    });
  }
);


/* =========================================================
   PROFILE
========================================================= */

app.get(
  "/api/profile",
  requireAuth,
  (req, res) => {
    const user = getUser(
      req.auth.sub
    );

    if (!user) {
      return res.status(404).json({
        error:
          "کاربر پیدا نشد."
      });
    }

    const wallet =
      getWallet(user.id);

    res.json({
      user: publicUser(user),
      wallet
    });
  }
);


app.put(
  "/api/profile",
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

    const user = getUser(
      req.auth.sub
    );

    res.json({
      user: publicUser(user)
    });
  }
);


/* =========================================================
   PROJECTS
========================================================= */

app.get(
  "/api/projects",
  (req, res) => {
    const status =
      cleanText(
        req.query.status,
        30
      );

    let projects;

    if (status) {
      projects = db
        .prepare(`
          SELECT
            p.*,
            u.name AS client_name
          FROM projects p
          LEFT JOIN users u
            ON u.id = p.client_id
          WHERE p.status = ?
          ORDER BY p.id DESC
        `)
        .all(status);
    } else {
      projects = db
        .prepare(`
          SELECT
            p.*,
            u.name AS client_name
          FROM projects p
          LEFT JOIN users u
            ON u.id = p.client_id
          ORDER BY p.id DESC
        `)
        .all();
    }

    res.json({
      projects
    });
  }
);


app.get(
  "/api/projects/:id",
  (req, res) => {
    const id =
      Number(req.params.id);

    const project = db
      .prepare(`
        SELECT
          p.*,
          u.name AS client_name,
          u.phone AS client_phone
        FROM projects p
        LEFT JOIN users u
          ON u.id = p.client_id
        WHERE p.id = ?
      `)
      .get(id);

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    const applications = db
      .prepare(`
        SELECT
          a.*,
          u.name AS freelancer_name,
          u.skills AS freelancer_skills,
          u.rating AS freelancer_rating
        FROM applications a
        JOIN users u
          ON u.id = a.freelancer_id
        WHERE a.project_id = ?
        ORDER BY a.id DESC
      `)
      .all(id);

    res.json({
      project,
      applications
    });
  }
);


app.post(
  "/api/projects",
  requireAuth,
  requireRole("client", "admin"),
  (req, res) => {
    const title = cleanText(
      req.body.title,
      150
    );

    const description = cleanText(
      req.body.description,
      3000
    );

    const budget = parseMoney(
      req.body.budget
    );

    if (!title) {
      return res.status(400).json({
        error:
          "عنوان پروژه را وارد کنید."
      });
    }

    if (!description) {
      return res.status(400).json({
        error:
          "توضیحات پروژه را وارد کنید."
      });
    }

    if (budget <= 0) {
      return res.status(400).json({
        error:
          "بودجه پروژه معتبر نیست."
      });
    }

    const result = db.prepare(`
      INSERT INTO projects
        (
          client_id,
          title,
          description,
          budget,
          status
        )
      VALUES
        (?, ?, ?, ?, 'open')
    `).run(
      req.auth.sub,
      title,
      description,
      budget
    );

    const project = db
      .prepare(`
        SELECT *
        FROM projects
        WHERE id = ?
      `)
      .get(result.lastInsertRowid);

    res.json({
      project
    });
  }
);


/* =========================================================
   APPLICATIONS
========================================================= */

app.post(
  "/api/projects/:id/apply",
  requireAuth,
  requireRole("freelancer"),
  (req, res) => {
    const projectId =
      Number(req.params.id);

    const project = db
      .prepare(`
        SELECT *
        FROM projects
        WHERE id = ?
      `)
      .get(projectId);

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
      project.client_id ===
      req.auth.sub
    ) {
      return res.status(400).json({
        error:
          "نمی‌توانید برای پروژه خودتان درخواست بفرستید."
      });
    }

    const existing = db
      .prepare(`
        SELECT id
        FROM applications
        WHERE project_id = ?
          AND freelancer_id = ?
      `)
      .get(
        projectId,
        req.auth.sub
      );

    if (existing) {
      return res.status(409).json({
        error:
          "قبلاً برای این پروژه درخواست داده‌اید."
      });
    }

    const message = cleanText(
      req.body.message,
      2000
    );

    const result = db.prepare(`
      INSERT INTO applications
        (
          project_id,
          freelancer_id,
          message,
          status
        )
      VALUES
        (?, ?, ?, 'pending')
    `).run(
      projectId,
      req.auth.sub,
      message
    );

    res.json({
      ok: true,
      application_id:
        result.lastInsertRowid
    });
  }
);


app.get(
  "/api/my-applications",
  requireAuth,
  requireRole("freelancer"),
  (req, res) => {
    const applications = db
      .prepare(`
        SELECT
          a.*,
          p.title,
          p.description,
          p.budget,
          p.status AS project_status
        FROM applications a
        JOIN projects p
          ON p.id = a.project_id
        WHERE a.freelancer_id = ?
        ORDER BY a.id DESC
      `)
      .all(req.auth.sub);

    res.json({
      applications
    });
  }
);


app.get(
  "/api/projects/:id/applications",
  requireAuth,
  (req, res) => {
    const projectId =
      Number(req.params.id);

    const project = db
      .prepare(`
        SELECT *
        FROM projects
        WHERE id = ?
      `)
      .get(projectId);

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    const isOwner =
      project.client_id ===
      req.auth.sub;

    const isAdmin =
      req.auth.role === "admin";

    if (!isOwner && !isAdmin) {
      return res.status(403).json({
        error:
          "دسترسی غیرمجاز."
      });
    }

    const applications = db
      .prepare(`
        SELECT
          a.*,
          u.name AS freelancer_name,
          u.phone AS freelancer_phone,
          u.skills AS freelancer_skills,
          u.rating AS freelancer_rating
        FROM applications a
        JOIN users u
          ON u.id = a.freelancer_id
        WHERE a.project_id = ?
        ORDER BY a.id DESC
      `)
      .all(projectId);

    res.json({
      project,
      applications
    });
  }
);


/* =========================================================
   SELECT FREELANCER
========================================================= */

app.post(
  "/api/projects/:id/select",
  requireAuth,
  requireRole("client", "admin"),
  (req, res) => {
    const projectId =
      Number(req.params.id);

    const freelancerId =
      Number(req.body.freelancer_id);

    const project = db
      .prepare(`
        SELECT *
        FROM projects
        WHERE id = ?
      `)
      .get(projectId);

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    if (
      req.auth.role !== "admin" &&
      project.client_id !==
        req.auth.sub
    ) {
      return res.status(403).json({
        error:
          "دسترسی غیرمجاز."
      });
    }

    if (
      project.status !== "open"
    ) {
      return res.status(400).json({
        error:
          "این پروژه دیگر باز نیست."
      });
    }

    const application = db
      .prepare(`
        SELECT *
        FROM applications
        WHERE project_id = ?
          AND freelancer_id = ?
      `)
      .get(
        projectId,
        freelancerId
      );

    if (!application) {
      return res.status(404).json({
        error:
          "درخواست فریلنسر پیدا نشد."
      });
    }

    const transaction =
      db.transaction(() => {
        db.prepare(`
          UPDATE projects
          SET
            freelancer_id = ?,
            status = 'assigned'
          WHERE id = ?
        `).run(
          freelancerId,
          projectId
        );

        db.prepare(`
          UPDATE applications
          SET status = 'accepted'
          WHERE id = ?
        `).run(
          application.id
        );

        db.prepare(`
          UPDATE applications
          SET status = 'rejected'
          WHERE project_id = ?
            AND id != ?
            AND status = 'pending'
        `).run(
          projectId,
          application.id
        );
      });

    transaction();

    res.json({
      ok: true
    });
  }
);


/* =========================================================
   PROJECT STATUS
========================================================= */

app.post(
  "/api/projects/:id/status",
  requireAuth,
  (req, res) => {
    const projectId =
      Number(req.params.id);

    const status =
      cleanText(
        req.body.status,
        30
      );

    const allowed = [
      "open",
      "assigned",
      "in_progress",
      "completed",
      "cancelled"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error:
          "وضعیت پروژه معتبر نیست."
      });
    }

    const project = db
      .prepare(`
        SELECT *
        FROM projects
        WHERE id = ?
      `)
      .get(projectId);

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    const allowedUser =
      project.client_id ===
        req.auth.sub ||
      project.freelancer_id ===
        req.auth.sub ||
      req.auth.role === "admin";

    if (!allowedUser) {
      return res.status(403).json({
        error:
          "دسترسی غیرمجاز."
      });
    }

    db.prepare(`
      UPDATE projects
      SET status = ?
      WHERE id = ?
    `).run(
      status,
      projectId
    );

    res.json({
      ok: true
    });
  }
);


/* =========================================================
   PAYMENT / COMPLETION
========================================================= */

app.post(
  "/api/projects/:id/pay",
  requireAuth,
  requireRole("client", "admin"),
  (req, res) => {
    const projectId =
      Number(req.params.id);

    const project = db
      .prepare(`
        SELECT *
        FROM projects
        WHERE id = ?
      `)
      .get(projectId);

    if (!project) {
      return res.status(404).json({
        error:
          "پروژه پیدا نشد."
      });
    }

    if (
      req.auth.role !== "admin" &&
      project.client_id !==
        req.auth.sub
    ) {
      return res.status(403).json({
        error:
          "شما مالک این پروژه نیستید."
      });
    }

    if (!project.freelancer_id) {
      return res.status(400).json({
        error:
          "هنوز فریلنسری برای پروژه انتخاب نشده است."
      });
    }

    const existingPayment =
      db
        .prepare(`
          SELECT *
          FROM project_payments
          WHERE project_id = ?
        `)
        .get(projectId);

    if (existingPayment) {
      return res.status(409).json({
        error:
          "پرداخت این پروژه قبلاً ثبت شده است."
      });
    }

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

    const settings = db
      .prepare(`
        SELECT commission_rate
        FROM platform_settings
        WHERE id = 1
      `)
      .get();

    const commissionRate =
      Number(
        settings?.commission_rate ??
          DEFAULT_COMMISSION
      );

    const grossAmount =
      parseMoney(project.budget);

    const commissionAmount =
      Math.round(
        grossAmount *
          commissionRate /
          100
      );

    const freelancerNet =
      grossAmount -
      commissionAmount;

    ensureWallet(
      project.client_id
    );

    ensureWallet(
      project.freelancer_id
    );

    ensureWallet(
      admin.id
    );

    const transaction =
      db.transaction(() => {
        const clientWallet =
          getWallet(
            project.client_id
          );

        if (
          Number(clientWallet.balance) <
          grossAmount
        ) {
          throw new Error(
            "INSUFFICIENT_BALANCE"
          );
        }

        db.prepare(`
          UPDATE wallets
          SET
            balance = balance - ?,
            total_spent =
              total_spent + ?
          WHERE user_id = ?
        `).run(
          grossAmount,
          grossAmount,
          project.client_id
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
            (?, 'payment', ?, ?)
        `).run(
          project.client_id,
          -grossAmount,
          `پرداخت پروژه #${projectId}`
        );

        db.prepare(`
          UPDATE wallets
          SET
            balance =
              balance + ?,
            total_income =
              total_income + ?
          WHERE user_id = ?
        `).run(
          freelancerNet,
          freelancerNet,
          project.freelancer_id
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
            (?, 'income', ?, ?)
        `).run(
          project.freelancer_id,
          freelancerNet,
          `درآمد پروژه #${projectId}`
        );

        db.prepare(`
          UPDATE wallets
          SET
            balance =
              balance + ?,
            total_income =
              total_income + ?
          WHERE user_id = ?
        `).run(
          commissionAmount,
          commissionAmount,
          admin.id
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
            (?, 'commission', ?, ?)
        `).run(
          admin.id,
          commissionAmount,
          `کمیسیون پروژه #${projectId}`
        );

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
              status
            )
          VALUES
            (?, ?, ?, ?, ?, ?, ?, 'completed')
        `).run(
          projectId,
          project.client_id,
          project.freelancer_id,
          grossAmount,
          commissionRate,
          commissionAmount,
          freelancerNet
        );

        db.prepare(`
          INSERT OR IGNORE INTO platform_ledger
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
          grossAmount,
          commissionRate,
          commissionAmount,
          freelancerNet
        );

        db.prepare(`
          UPDATE projects
          SET status = 'completed'
          WHERE id = ?
        `).run(projectId);
      });

    try {
      transaction();
    } catch (error) {
      if (
        error.message ===
        "INSUFFICIENT_BALANCE"
      ) {
        return res.status(400).json({
          error:
            "موجودی کیف پول کارفرما کافی نیست."
        });
      }

      console.error(
        "PAYMENT ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "پرداخت انجام نشد."
      });
    }

    res.json({
      ok: true,
      gross_amount: grossAmount,
      commission_rate:
        commissionRate,
      commission_amount:
        commissionAmount,
      freelancer_net:
        freelancerNet
    });
  }
);


/* =========================================================
   WALLET
========================================================= */

app.get(
  "/api/wallet",
  requireAuth,
  (req, res) => {
    const wallet =
      getWallet(req.auth.sub);

    const transactions =
      db
        .prepare(`
          SELECT *
          FROM wallet_transactions
          WHERE user_id = ?
          ORDER BY id DESC
        `)
        .all(req.auth.sub);

    res.json({
      wallet,
      transactions
    });
  }
);


app.post(
  "/api/wallet/deposit",
  requireAuth,
  (req, res) => {
    const amount =
      parseMoney(req.body.amount);

    if (amount <= 0) {
      return res.status(400).json({
        error:
          "مبلغ معتبر نیست."
      });
    }

    ensureWallet(
      req.auth.sub
    );

    db.prepare(`
      UPDATE wallets
      SET
        balance =
          balance + ?
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
      "افزایش موجودی آزمایشی"
    );

    res.json({
      ok: true,
      wallet:
        getWallet(
          req.auth.sub
        )
    });
  }
);


app.post(
  "/api/wallet/withdraw",
  requireAuth,
  (req, res) => {
    const amount =
      parseMoney(req.body.amount);

    if (amount <= 0) {
      return res.status(400).json({
        error:
          "مبلغ معتبر نیست."
      });
    }

    const wallet =
      getWallet(
        req.auth.sub
      );

    if (
      Number(wallet.balance) <
      amount
    ) {
      return res.status(400).json({
        error:
          "موجودی کافی نیست."
      });
    }

    db.prepare(`
      UPDATE wallets
      SET
        balance =
          balance - ?
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
      -amount,
      "برداشت آزمایشی"
    );

    res.json({
      ok: true,
      wallet:
        getWallet(
          req.auth.sub
        )
    });
  }
);


/* =========================================================
   REWARDS
========================================================= */

app.get(
  "/api/rewards",
  requireAuth,
  (req, res) => {
    const user = getUser(
      req.auth.sub
    );

    const rewards = db
      .prepare(`
        SELECT *
        FROM reward_claims
        WHERE user_id = ?
        ORDER BY id DESC
      `)
      .all(req.auth.sub);

    res.json({
      points:
        Number(user?.points || 0),
      rewards
    });
  }
);


/* =========================================================
   ADMIN
========================================================= */

const adminOnly =
  requireRole("admin");


app.get(
  "/api/admin/overview",
  requireAuth,
  adminOnly,
  (req, res) => {
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

    const usersCount =
      db
        .prepare(`
          SELECT COUNT(*) AS count
          FROM users
          WHERE role != 'admin'
        `)
        .get().count;

    const freelancersCount =
      db
        .prepare(`
          SELECT COUNT(*) AS count
          FROM users
          WHERE role = 'freelancer'
        `)
        .get().count;

    const clientsCount =
      db
        .prepare(`
          SELECT COUNT(*) AS count
          FROM users
          WHERE role = 'client'
        `)
        .get().count;

    const projectsCount =
      db
        .prepare(`
          SELECT COUNT(*) AS count
          FROM projects
        `)
        .get().count;

    const completedProjects =
      db
        .prepare(`
          SELECT COUNT(*) AS count
          FROM projects
          WHERE status = 'completed'
        `)
        .get().count;

    const totalVolume =
      db
        .prepare(`
          SELECT
            COALESCE(
              SUM(gross_amount),
              0
            ) AS total
          FROM platform_ledger
        `)
        .get().total;

    const totalCommission =
      db
        .prepare(`
          SELECT
            COALESCE(
              SUM(commission_amount),
              0
            ) AS total
          FROM platform_ledger
        `)
        .get().total;

    const totalFreelancerNet =
      db
        .prepare(`
          SELECT
            COALESCE(
              SUM(freelancer_net),
              0
            ) AS total
          FROM platform_ledger
        `)
        .get().total;

    const settings =
      db
        .prepare(`
          SELECT *
          FROM platform_settings
          WHERE id = 1
        `)
        .get();

    res.json({
      admin,
      users: usersCount,
      freelancers:
        freelancersCount,
      clients:
        clientsCount,
      projects:
        projectsCount,
      completed_projects:
        completedProjects,
      total_volume:
        Number(totalVolume || 0),
      total_commission:
        Number(totalCommission || 0),
      total_freelancer_net:
        Number(
          totalFreelancerNet || 0
        ),
      commission_rate:
        Number(
          settings?.commission_rate ??
            DEFAULT_COMMISSION
        )
    });
  }
);


app.get(
  "/api/admin/users",
  requireAuth,
  adminOnly,
  (_req, res) => {
    const users = db
      .prepare(`
        SELECT
          u.id,
          u.name,
          u.phone,
          u.role,
          u.points,
          u.rating,
          u.created_at,
          COALESCE(
            w.balance,
            0
          ) AS balance,
          COALESCE(
            w.total_income,
            0
          ) AS total_income,
          COALESCE(
            w.total_spent,
            0
          ) AS total_spent
        FROM users u
        LEFT JOIN wallets w
          ON w.user_id = u.id
        ORDER BY u.id DESC
      `)
      .all();

    res.json({
      users
    });
  }
);


app.get(
  "/api/admin/projects",
  requireAuth,
  adminOnly,
  (_req, res) => {
    const projects = db
      .prepare(`
        SELECT
          p.*,
          c.name AS client_name,
          f.name AS freelancer_name
        FROM projects p
        LEFT JOIN users c
          ON c.id = p.client_id
        LEFT JOIN users f
          ON f.id = p.freelancer_id
        ORDER BY p.id DESC
      `)
      .all();

    res.json({
      projects
    });
  }
);


app.get(
  "/api/admin/ledger",
  requireAuth,
  adminOnly,
  (_req, res) => {
    const ledger = db
      .prepare(`
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
        ORDER BY l.id DESC
      `)
      .all();

    res.json({
      ledger
    });
  }
);


app.get(
  "/api/admin/settings",
  requireAuth,
  adminOnly,
  (_req, res) => {
    const settings =
      db
        .prepare(`
          SELECT *
          FROM platform_settings
          WHERE id = 1
        `)
        .get();

    res.json({
      settings
    });
  }
);


app.put(
  "/api/admin/settings",
  requireAuth,
  adminOnly,
  (req, res) => {
    let commission =
      Number(
        req.body.commission_rate
      );

    if (!Number.isFinite(commission)) {
      return res.status(400).json({
        error:
          "درصد کمیسیون معتبر نیست."
      });
    }

    commission =
      Math.min(
        50,
        Math.max(
          0,
          commission
        )
      );

    db.prepare(`
      UPDATE platform_settings
      SET
        commission_rate = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = 1
    `).run(commission);

    res.json({
      ok: true,
      commission_rate:
        commission
    });
  }
);


/* =========================================================
   STATIC FRONTEND
========================================================= */

app.use(
  express.static(
    FRONTEND_DIR,
    {
      index: "index.html"
    }
  )
);


/* =========================================================
   SPA FALLBACK
========================================================= */

app.get(
  "*",
  (_req, res) => {
    res.sendFile(
      path.join(
        FRONTEND_DIR,
        "index.html"
      )
    );
  }
);


/* =========================================================
   START
========================================================= */

migrate();

ensureAdminFromEnv();

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Skillora v15 Plus running at http://localhost:${PORT}`
    );
  }
);
