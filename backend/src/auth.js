const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";
const COOKIE_NAME = "skillora_session";

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

function verifyPassword(password, stored) {
  const [saltHex, hashHex] = String(stored).split(":");
  if (!saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(password, salt, expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
}

function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000,
    path: "/"
  });
}

function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: "ورود لازم است." });
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "نشست ورود معتبر نیست یا منقضی شده است." });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.role)) {
      return res.status(403).json({ error: "دسترسی برای این نقش مجاز نیست." });
    }
    next();
  };
}

module.exports = {
  COOKIE_NAME,
  hashPassword,
  verifyPassword,
  signToken,
  setSessionCookie,
  requireAuth,
  requireRole
};
