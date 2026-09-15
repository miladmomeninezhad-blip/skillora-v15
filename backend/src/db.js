const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const root = path.resolve(__dirname, "../..");
const databaseDir = path.join(root, "database");
fs.mkdirSync(databaseDir, { recursive: true });

const db = new Database(path.join(databaseDir, "skillora.sqlite"));
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");

const schema = fs.readFileSync(path.join(databaseDir, "schema.sql"), "utf8");
db.exec(schema);

module.exports = db;
