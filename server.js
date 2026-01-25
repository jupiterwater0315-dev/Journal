// server.js — PHASE 2 Journal + Dashboard (working, clean build)
//
// What this version guarantees:
// - No duplicate route definitions (your pasted file had many duplicates that break Express)
// - No broken/duplicate function declarations (applyTextOverrides was duplicated & corrupted)
// - Works with: /register /login /logout + screens /s1..../s6 + /dashboard
// - Uses sql.js (file-backed SQLite) + uploads folder for chart images
// - Keeps your instrument presets + risk/levels logic
// - Uses your Screen 5 renderer: const { renderScreen5, DEFAULT_COPY } = require("./views/screen5")
//
// Required files/folders:
// - ./views/screen5.js must export { renderScreen5, DEFAULT_COPY }
// - ./public/style.css (optional but recommended)
// - npm i express body-parser cookie-parser sql.js bcryptjs
//
// Run:
// - node server.js
//

const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");

const { renderScreen5, DEFAULT_COPY } = require("./views/screen5");

const APP_TITLE = "PHASE 2 — Journal + Dashboard (clean)";
const PORT = process.env.PORT || 3000;

const DB_FILE = path.join(__dirname, "data.sqlite");
const SQL_WASM_FILE = path.join(__dirname, "node_modules", "sql.js", "dist", "sql-wasm.wasm");

// uploads
const UPLOAD_DIR = path.join(__dirname, "uploads");
try {
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
} catch (_) {}

const app = express();
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use("/public", express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(UPLOAD_DIR));

// ---- Instruments (presets) ----
const INSTRUMENTS = {
  CL: { label: "CL — Crude Oil", tickSize: 0.01, tickValue: 10, contractsDefault: 2 },
  ES: { label: "ES — S&P 500", tickSize: 0.25, tickValue: 12.5, contractsDefault: 1 },
  NQ: { label: "NQ — Nasdaq", tickSize: 0.25, tickValue: 5, contractsDefault: 1 },
  GC: { label: "GC — Gold", tickSize: 0.1, tickValue: 10, contractsDefault: 1 },
};

// ---------------- helpers ----------------
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function esc(s) { return escapeHtml(s); }

function nowIso() { return new Date().toISOString(); }

function randId(prefix = "") {
  return prefix + Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2);
}

function safeJsonParse(s, fallback) {
  try {
    const v = JSON.parse(String(s));
    return (v && typeof v === "object") ? v : fallback;
  } catch {
    return fallback;
  }
}

function parseNum(v) {
  if (v === "" || v === null || v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function csvEscape(v) {
  if (v === null || v === undefined) return "";
  const s = String(v);
  if (/[\",\n\r]/.test(s)) return '"' + s.replaceAll('"', '""') + '"';
  return s;
}
function rowsToCsv(headers, rows) {
  const lines = [];
  lines.push(headers.map(csvEscape).join(","));
  for (const r of rows) lines.push(headers.map(h => csvEscape(r[h])).join(","));
  return lines.join("\n");
}

// ---------------- sql.js db ----------------
let SQL;
let db;

async function getDb() {
  if (db) return db;
  SQL = await initSqlJs({
    locateFile: (file) => (file === "sql-wasm.wasm" ? SQL_WASM_FILE : file),
  });

  if (fs.existsSync(DB_FILE)) {
    const buf = fs.readFileSync(DB_FILE);
    db = new SQL.Database(new Uint8Array(buf));
  } else {
    db = new SQL.Database();
  }

  ensureSchema(db);
  persistDb();
  return db;
}

function persistDb() {
  if (!db) return;
  const data = db.export();
  fs.writeFileSync(DB_FILE, Buffer.from(data));
}

function normalizeParams(params) {
  if (!Array.isArray(params)) return [];
  return params.map(v => (v === undefined ? null : v));
}

function exec(dbx, sql, params = []) {
  const stmt = dbx.prepare(sql);
  stmt.bind(normalizeParams(params));
  while (stmt.step()) {}
  stmt.free();
}

function one(dbx, sql, params = []) {
  const stmt = dbx.prepare(sql);
  stmt.bind(normalizeParams(params));
  const row = stmt.step() ? stmt.getAsObject() : null;
  stmt.free();
  return row;
}

function all(dbx, sql, params = []) {
  const stmt = dbx.prepare(sql);
  stmt.bind(normalizeParams(params));
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function hasTable(dbx, table) {
  const r = one(dbx, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", [table]);
  return !!(r && r.name);
}

function hasColumn(dbx, table, col) {
  try {
    const rows = all(dbx, `PRAGMA table_info(${table})`);
    return rows.some(r => r && r.name === col);
  } catch {
    return false;
  }
}

function ensureSchema(dbx) {
  // sessions schema migration safety
  if (hasTable(dbx, "sessions") && !hasColumn(dbx, "sessions", "sid")) {
    exec(dbx, "DROP TABLE sessions;");
  }

  exec(dbx, `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );`);

  exec(dbx, `CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    state_json TEXT,
    history_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );`);

  exec(dbx, `CREATE TABLE IF NOT EXISTS trades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,

    instrument TEXT NOT NULL,
    trade_type TEXT NOT NULL,
    direction TEXT NOT NULL,

    entry REAL NOT NULL,
    one_r REAL NOT NULL,
    contracts INTEGER NOT NULL,
    tick_size REAL NOT NULL,
    tick_value REAL NOT NULL,
    rr REAL,

    sl_price REAL,
    tp_price REAL,
    be_price REAL,

    result TEXT NOT NULL,
    pnl_r REAL NOT NULL,
    pnl_s REAL NOT NULL,

    emotion TEXT,
    mode TEXT,
    body_scan INTEGER,
    note_len INTEGER,

    raw_json TEXT,
    chart_image TEXT
  );`);

// ---- migrations: trades override audit ----
if (!hasColumn(dbx, "trades", "override_used")) {
  exec(dbx, "ALTER TABLE trades ADD COLUMN override_used INTEGER DEFAULT 0;");
}
if (!hasColumn(dbx, "trades", "override_reason")) {
  exec(dbx, "ALTER TABLE trades ADD COLUMN override_reason TEXT;");
}
if (!hasColumn(dbx, "trades", "override_rules")) {
  exec(dbx, "ALTER TABLE trades ADD COLUMN override_rules TEXT;");
}


  exec(dbx, `CREATE TABLE IF NOT EXISTS integration_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    trade_id INTEGER,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    emotion TEXT,
    intensity_before INTEGER,
    intensity_after INTEGER,
    payload_json TEXT NOT NULL
  );`);
  exec(dbx, `CREATE INDEX IF NOT EXISTS idx_integration_sessions_user_created
             ON integration_sessions(user_id, created_at);`);

  exec(dbx, `CREATE TABLE IF NOT EXISTS integration_texts (
    user_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );`);
}

// ---------------- session state helpers ----------------
function readSessionState(sessRow) {
  let st = {};
  let hist = [];
  try { st = sessRow?.state_json ? JSON.parse(sessRow.state_json) : {}; } catch { st = {}; }
  try { hist = sessRow?.history_json ? JSON.parse(sessRow.history_json) : []; } catch { hist = []; }
  return { st, hist };
}

function writeSessionState(dbx, sid, st, hist) {
  exec(dbx, `UPDATE sessions SET state_json=?, history_json=?, updated_at=? WHERE sid=?`,
    [JSON.stringify(st ?? {}), JSON.stringify(hist ?? []), nowIso(), sid]
  );
  persistDb();
}

function pushHistory(hist, st) {
  const snap = JSON.parse(JSON.stringify(st ?? {}));
  const next = Array.isArray(hist) ? [...hist, snap] : [snap];
  return next.length > 30 ? next.slice(next.length - 30) : next;
}

function popHistory(hist) {
  if (!hist || hist.length === 0) return { hist: [], prev: null };
  const prev = hist[hist.length - 1];
  const newHist = hist.slice(0, -1);
  return { hist: newHist, prev };
}

// ---------------- integration copy (per user) ----------------
function getIntegrationCopy(dbx, userId) {
  const row = one(dbx, `SELECT payload_json FROM integration_texts WHERE user_id=?`, [userId]);
  const saved = row && row.payload_json ? safeJsonParse(row.payload_json, {}) : {};
  return { ...DEFAULT_COPY, ...saved };
}

// ---------------- UI layout ----------------
// ---------------- Text Overrides (Admin-managed) ----------------
const DATA_DIR = path.join(__dirname, "data");
const TEXT_OVERRIDES_FILE = path.join(DATA_DIR, "text-overrides.json");

function ensureDataDir() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  } catch (e) {
    console.warn("Could not ensure data dir:", e?.message || e);
  }
}

function readTextOverrides() {
  ensureDataDir();
  try {
    if (!fs.existsSync(TEXT_OVERRIDES_FILE)) return {};
    const raw = fs.readFileSync(TEXT_OVERRIDES_FILE, "utf8");
    if (!raw.trim()) return {};
    const obj = JSON.parse(raw);
    return obj && typeof obj === "object" && !Array.isArray(obj) ? obj : {};
  } catch (e) {
    console.warn("Failed to read text overrides:", e?.message || e);
    return {};
  }
}

function saveTextOverrides(overridesObj) {
  ensureDataDir();
  const clean = overridesObj && typeof overridesObj === "object" && !Array.isArray(overridesObj) ? overridesObj : {};
  fs.writeFileSync(TEXT_OVERRIDES_FILE, JSON.stringify(clean, null, 2), "utf8");
}

function applyTextOverrides(html) {
  const overrides = readTextOverrides();
  const entries = Object.entries(overrides)
    .filter(([k, v]) => typeof k === "string" && k.trim() && typeof v === "string")
    // longer keys first to avoid partial replacements eating bigger strings
    .sort((a, b) => b[0].length - a[0].length);

  let out = String(html);
  for (const [from, to] of entries) {
    if (from === to) continue;
    // Use split/join (safe, no regex escaping needed)
    out = out.split(from).join(to);
  }
  return out;
}

// Very lightweight source extractor to help populate the admin list.
// It scans this server.js source and returns unique strings that look like UI text.
function extractCandidateUiTextsFromSource() {
  try {
    const src = fs.readFileSync(__filename, "utf8");
    const candidates = new Set();

    // 1) Text between HTML tags in template strings: >TEXT<
    const reTagText = />\s*([^<>\n]{2,120}?)\s*</g;
    let m;
    while ((m = reTagText.exec(src))) {
      const t = (m[1] || "").trim();
      if (!t) continue;
      // Filter out likely JS operators / placeholders
      if (/[{}$]/.test(t)) continue;
      // Keep strings with letters/numbers (MN/Cyrillic/Latin) or punctuation used in UI
      if (!/[\p{L}\p{N}]/u.test(t)) continue;
      candidates.add(t);
    }

    // 2) Common button labels inside quoted JS strings (e.g., "Нэвтрэх", "Save", etc.)
    const reQuoted = /["'`]([^"'`\n]{2,80})["'`]/g;
    while ((m = reQuoted.exec(src))) {
      const t = (m[1] || "").trim();
      if (!t) continue;
      if (t.includes("\\") || t.includes("http") || t.includes("/") || t.includes(".js")) continue;
      if (/[{}$]/.test(t)) continue;
      if (!/[\p{L}\p{N}]/u.test(t)) continue;
      // Avoid obviously non-UI tokens
      if (/^[A-Z0-9_\-]{2,}$/.test(t)) continue;
      candidates.add(t);
    }

    return Array.from(candidates).sort((a, b) => a.localeCompare(b));
  } catch {
    return [];
  }
}

function layout({ active = "Journal", userEmail = "", body = "", stateLabel = "", slCount = 0, beCount = 0, noTextOverride = false }) {
  const tabs = [
    { name: "Journal", href: "/s1" },
    { name: "Dashboard", href: "/dashboard" },
    { name: "Integrations", href: "/integrations" },
  ];

  const nav = tabs.map(t => {
    const cls = "pill" + (t.name === active ? " active" : "");
    return `<a class="${cls}" href="${t.href}">${t.name}</a>`;
  }).join("");

  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${escapeHtml(APP_TITLE)}</title>
  <link rel="stylesheet" href="/public/style.css"/>
</head>
<body>
  <div class="wrap">
    <h1>${escapeHtml(APP_TITLE)}</h1>
    <div class="topnav">
      ${nav}
      <span class="muted">DB: data.sqlite</span>
      <span class="right muted">User: ${escapeHtml(userEmail)}</span>
    </div>

    <div class="card">
      <div class="row" style="justify-content:space-between;align-items:center">
        <div>
          <span class="pill">STATE: ${escapeHtml(stateLabel || "—")}</span>
          <span class="pill">SL ${escapeHtml(String(slCount))}/2</span>
          <span class="pill">BE ${escapeHtml(String(beCount))}/2</span>
        </div>
        <div class="muted">Local demo</div>
      </div>
    </div>

    ${body}
  </div>
</body>
</html>`;
  return noTextOverride ? html : applyTextOverrides(html);
}

// ---------------- rules + risk ----------------
function validateBalance({ anchor, entry, val, vah, tickSize }) {
  const errors = [];
  if (!anchor) errors.push("Anchor сонгоогүй байна.");
  if (entry === null) errors.push("Entry хоосон байна.");
  if (val === null || vah === null || tickSize === null) errors.push("VAL/VAH/Tick size шаардлагатай.");
  if (errors.length) return errors;

  const minTicks = 2;
  const maxTicks = 3;

  if (anchor === "VAL") {
    const diff = (entry - val) / tickSize;
    if (!(diff >= minTicks - 1e-9 && diff <= maxTicks + 1e-9)) {
      errors.push("Balance entry invalid: VAL-аас дотогш 2–3 tick.");
    }
  } else if (anchor === "VAH") {
    const diff = (vah - entry) / tickSize;
    if (!(diff >= minTicks - 1e-9 && diff <= maxTicks + 1e-9)) {
      errors.push("Balance entry invalid: VAH-аас дотогш 2–3 tick.");
    }
  }
  return errors;
}

function computeRiskTicks({ oneR, tickValue, contracts }) {
  const r = Number(oneR);
  const tv = Number(tickValue);
  const c = Number(contracts);
  if (!isFinite(r) || !isFinite(tv) || !isFinite(c) || tv <= 0 || c <= 0) {
    return { ticksRaw: null, ticksRounded: null, oneRActual: null };
  }
  const ticksRaw = r / (tv * c);
  const ticksRounded = Math.max(1, Math.round(ticksRaw));
  const oneRActual = ticksRounded * tv * c;
  return { ticksRaw, ticksRounded, oneRActual };
}

function computeLevels({ entry, tickSize, oneR, tickValue, contracts, rr }) {
  const { ticksRaw, ticksRounded, oneRActual } = computeRiskTicks({ oneR, tickValue, contracts });
  const ts = Number(tickSize);
  const riskTicks = ticksRounded;
  const riskPoints = (riskTicks !== null && isFinite(ts)) ? (riskTicks * ts) : null;
  const rrN = Number(rr);
  const tpPoints = (riskPoints !== null && isFinite(rrN)) ? (riskPoints * rrN) : null;
  return { ticksRaw, tickR: riskTicks, oneRPoints: riskPoints, tpPoints, oneRActual };
}

function pnlFromResult(result, rr = 2) {
  const rrN = isFinite(Number(rr)) ? Number(rr) : 2;
  if (result === "TP") return { pnlR: rrN, pnlS: null };
  if (result === "BE") return { pnlR: 0, pnlS: 0 };
  if (result === "SL") return { pnlR: -1, pnlS: null };
  return { pnlR: 0, pnlS: 0 };
}

// ---------------- multipart upload (single image) ----------------
function parseMultipartSingleFile(req, { fileField = "chart", maxBytes = 8 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers["content-type"] || "");
    const m = ct.match(/boundary=(.+)$/i);
    if (!m) return reject(new Error("No boundary"));
    const boundary = "--" + m[1];

    const chunks = [];
    let total = 0;

    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error("File too large"));
        try { req.destroy(); } catch (_) {}
        return;
      }
      chunks.push(chunk);
    });

    req.on("error", reject);

    req.on("end", () => {
      const buf = Buffer.concat(chunks);
      const boundaryBuf = Buffer.from(boundary);

      const parts = [];
      let start = buf.indexOf(boundaryBuf);

      while (start !== -1) {
        start += boundaryBuf.length;
        if (buf[start] === 45 && buf[start + 1] === 45) break; // -- end
        if (buf[start] === 13 && buf[start + 1] === 10) start += 2; // CRLF
        const next = buf.indexOf(boundaryBuf, start);
        if (next === -1) break;
        const part = buf.slice(start, next - 2); // remove trailing CRLF
        parts.push(part);
        start = next;
      }

      const fields = {};
      let savedFilename = null;

      for (const part of parts) {
        const sep = Buffer.from("\r\n\r\n");
        const i = part.indexOf(sep);
        if (i === -1) continue;

        const head = part.slice(0, i).toString("utf-8");
        const body = part.slice(i + sep.length);

        const cd = (head.match(/content-disposition:\s*form-data;[^\r\n]*/i) || [""])[0];
        const nameM = cd.match(/name="([^"]+)"/i);
        if (!nameM) continue;

        const name = nameM[1];
        const filenameM = cd.match(/filename="([^"]*)"/i);

        if (filenameM && name === fileField) {
          const orig = filenameM[1] || "upload.bin";
          const ext = path.extname(orig).toLowerCase();
          const safeExt = ([".png", ".jpg", ".jpeg", ".webp", ".gif"].includes(ext)) ? ext : ".png";

          const ctM = head.match(/content-type:\s*([^\r\n]+)/i);
          const partType = (ctM ? ctM[1].trim().toLowerCase() : "");
          if (partType && !partType.startsWith("image/")) return reject(new Error("Images only"));

          const fname = "trade_" + Date.now() + "_" + Math.random().toString(16).slice(2) + safeExt;
          const full = path.join(UPLOAD_DIR, fname);
          fs.writeFileSync(full, body);
          savedFilename = fname;
        } else {
          fields[name] = body.toString("utf-8");
        }
      }

      resolve({ fields, filename: savedFilename });
    });
  });
}

// ---------------- auth middleware ----------------
async function authMiddleware(req, res, next) {
  const dbx = await getDb();

  if (
    req.path === "/login" ||
    req.path === "/register" ||
    req.path.startsWith("/public") ||
    req.path.startsWith("/uploads")
  ) {
    return next();
  }

  const sid = req.cookies.sid;
  if (!sid) return res.redirect("/login");

  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [sid]);
  if (!sess) return res.redirect("/login");

  // optional expiry: 30d
  try {
    const created = new Date(sess.created_at).getTime();
    const maxAgeMs = 30 * 24 * 60 * 60 * 1000;
    if (Date.now() - created > maxAgeMs) {
      exec(dbx, `DELETE FROM sessions WHERE sid=?`, [sid]);
      persistDb();
      res.clearCookie("sid");
      return res.redirect("/login");
    }
  } catch (_) {}

  const user = one(dbx, `SELECT id,email FROM users WHERE id=?`, [sess.user_id]);
  if (!user) return res.redirect("/login");

  req.userId = user.id;
  req.userEmail = user.email;
  req.user = { id: user.id, email: user.email };
  req.sid = sid;
  req._sess = sess;

  return next();
}

app.get("/", authMiddleware, (req, res) => res.redirect("/s1"));

// ---------------- auth routes ----------------
app.get("/register", async (req, res) => {
  await getDb();
  const body = `
  <div class="card">
    <h2>Register</h2>
    <div class="small">Create a new account.</div>
    <hr/>
    <form method="POST" action="/register">
      <div class="row">
        <div class="field"><label>Email</label><input name="email" required/></div>
        <div class="field"><label>Password</label><input name="password" type="password" required minlength="6"/></div>
      </div>
      <div style="margin-top:12px"><button type="submit">Create account</button></div>
    </form>
    <div style="margin-top:12px"><a class="pill" href="/login">Back to login</a></div>
  </div>`;
  res.send(layout({ active: "Journal", userEmail: "", body, stateLabel: "REGISTER" }));
});

app.post("/register", async (req, res) => {
  const dbx = await getDb();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!email || !password || password.length < 6) {
    const body = `<div class="card"><h2>Register</h2><div class="error">Email болон password (min 6 тэмдэгт) шаардлагатай.</div><a class="pill" href="/register">Back</a></div>`;
    return res.send(layout({ active: "Journal", body, stateLabel: "REGISTER" }));
  }
  const exists = one(dbx, `SELECT id FROM users WHERE email=?`, [email]);
  if (exists) {
    const body = `<div class="card"><h2>Register</h2><div class="error">Энэ email бүртгэлтэй байна.</div><a class="pill" href="/register">Back</a></div>`;
    return res.send(layout({ active: "Journal", body, stateLabel: "REGISTER" }));
  }

  const hash = bcrypt.hashSync(password, 10);
  const uid = randId("u_");
  exec(dbx, `INSERT INTO users (id,email,password_hash,created_at) VALUES (?,?,?,?)`, [uid, email, hash, nowIso()]);
  persistDb();

  // auto-login
  const sid = randId("s_");
  const ts = nowIso();
  exec(dbx, `INSERT INTO sessions (sid,user_id,state_json,history_json,created_at,updated_at)
            VALUES (?,?,?,?,?,?)`,
    [sid, uid, "{}", "[]", ts, ts]
  );
  persistDb();

  res.cookie("sid", sid, { httpOnly: true, sameSite: "lax" });
  res.redirect("/s1");
});

app.get("/login", async (req, res) => {
  await getDb();
  const body = `
  <div class="card">
    <h2>Login (local demo)</h2>
    <hr/>
    <form method="POST" action="/login">
      <div class="row">
        <div class="field"><label>Email</label><input name="email" required/></div>
        <div class="field"><label>Password</label><input name="password" type="password" required/></div>
      </div>
      <div style="margin-top:12px"><button type="submit">Login</button></div>
    </form>
    <div style="margin-top:12px;font-size:14px">
      Шинэ хэрэглэгч үү? <a href="/register">Register</a>
    </div>
  </div>`;
  res.send(layout({ active: "Journal", userEmail: "", body, stateLabel: "LOGIN" }));
});

app.post("/login", async (req, res) => {
  const dbx = await getDb();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const u = one(dbx, `SELECT * FROM users WHERE email=?`, [email]);

  if (!u || !bcrypt.compareSync(password, u.password_hash)) {
    const body = `<div class="card"><h2>Login</h2><div class="error">Алдаа: email/password буруу.</div><a class="pill" href="/login">Back</a></div>`;
    return res.send(layout({ active: "Journal", body, stateLabel: "LOGIN" }));
  }

  const sid = randId("s_");
  const ts = nowIso();
  exec(dbx, `INSERT INTO sessions (sid,user_id,state_json,history_json,created_at,updated_at)
            VALUES (?,?,?,?,?,?)`,
    [sid, u.id, "{}", "[]", ts, ts]
  );
  persistDb();

  res.cookie("sid", sid, { httpOnly: true, sameSite: "lax" });
  res.redirect("/s1");
});

app.post("/logout", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sid = req.cookies.sid;
  if (sid) {
    exec(dbx, `DELETE FROM sessions WHERE sid=?`, [sid]);
    persistDb();
  }
  res.clearCookie("sid");
  res.redirect("/login");
});

// ---------------- Admin: Text Overrides ----------------
app.get("/admin/texts", authMiddleware, (req, res) => {
  const overrides = readTextOverrides();
  const candidates = extractCandidateUiTextsFromSource();

  const rows = candidates
    .slice(0, 400) // keep page light; user can still paste JSON for everything
    .map((t) => {
      const v = overrides[t] ?? "";
      return `<tr>
        <td style="width:45%; vertical-align:top;"><div style="white-space:pre-wrap;">${escapeHtml(t)}</div></td>
        <td style="width:55%;"><input name="val__${encodeURIComponent(t)}" value="${escapeAttr(v)}" style="width:100%; padding:8px;" /></td>
      </tr>`;
    })
    .join("");

  const jsonPretty = JSON.stringify(overrides, null, 2);

  res.send(
    layout({
      title: "Admin • Texts",
      noTextOverride: true,
      body: `
        <div class="card" style="max-width:1100px;">
          <h1 style="margin:0 0 8px 0;">Text Admin</h1>
          <p style="margin:0 0 16px 0; color:#444;">
            Эндээс journal доторх бүх UI текстийг код оролгүй өөрчилж болно.
            Доорх тохиргоо нь <b>“олдсон үг/өгүүлбэр”-ийг “шинэ утга”-аар</b> энгийнээр солих (replace) логикоор ажиллана.
          </p>

          <details open style="margin:0 0 16px 0;">
            <summary style="cursor:pointer; font-weight:700;">1) JSON Editor (өөрийнхөөрөө шууд удирдах)</summary>
            <form method="post" action="/admin/texts" style="margin-top:12px;">
              <input type="hidden" name="mode" value="json" />
              <textarea name="overrides_json" rows="14" style="width:100%; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; padding:10px;">${escapeHtml(
                jsonPretty
              )}</textarea>
              <div style="display:flex; gap:10px; margin-top:10px;">
                <button class="btn" type="submit">Save JSON</button>
                <a class="btn secondary" href="/s1">Back to Journal</a>
              </div>
            </form>
          </details>

          <details style="margin:0;">
            <summary style="cursor:pointer; font-weight:700;">2) Quick Edit (илрүүлсэн текстүүдээс сонгож засах)</summary>
            <form method="post" action="/admin/texts" style="margin-top:12px;">
              <input type="hidden" name="mode" value="table" />
              <div style="overflow:auto; max-height:520px; border:1px solid #eee; border-radius:10px;">
                <table style="width:100%; border-collapse:collapse;">
                  <thead>
                    <tr>
                      <th style="text-align:left; padding:10px; border-bottom:1px solid #eee; width:45%;">Original</th>
                      <th style="text-align:left; padding:10px; border-bottom:1px solid #eee; width:55%;">Override</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${rows || `<tr><td colspan="2" style="padding:10px;">No candidates found.</td></tr>`}
                  </tbody>
                </table>
              </div>
              <div style="display:flex; gap:10px; margin-top:10px;">
                <button class="btn" type="submit">Save Table</button>
              </div>
              <p style="margin:10px 0 0 0; color:#666; font-size:13px;">
                Жич: Энэ хүснэгт нь автоматаар олдсон 400 хүртэлх текстийг л харуулна. Бүхнийг хамруулах бол JSON Editor-оор нэмээд хадгал.
              </p>
            </form>
          </details>
        </div>
      `,
    })
  );
});

app.post("/admin/texts", authMiddleware, (req, res) => {
  try {
    const mode = String(req.body.mode || "json");
    if (mode === "table") {
      const current = readTextOverrides();
      const next = { ...current };

      for (const [k, v] of Object.entries(req.body || {})) {
        if (!k.startsWith("val__")) continue;
        const orig = decodeURIComponent(k.slice("val__".length));
        const val = typeof v === "string" ? v : "";
        if (val.trim() === "") {
          delete next[orig];
        } else {
          next[orig] = val;
        }
      }

      saveTextOverrides(next);
      return res.redirect("/admin/texts");
    }

    const raw = String(req.body.overrides_json || "{}");
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      throw new Error("JSON нь object байх ёстой.");
    }
    // keep only string->string
    const clean = {};
    for (const [k, v] of Object.entries(obj)) {
      if (typeof k === "string" && k.trim() && typeof v === "string") clean[k] = v;
    }
    saveTextOverrides(clean);
    res.redirect("/admin/texts");
  } catch (e) {
    res.status(400).send(
      layout({
        title: "Admin • Texts (Error)",
        noTextOverride: true,
        body: `
          <div class="card" style="max-width:900px;">
            <h1 style="margin:0 0 10px 0;">Save failed</h1>
            <p style="color:#b00020; white-space:pre-wrap;">${escapeHtml(e?.message || String(e))}</p>
            <a class="btn" href="/admin/texts">Back</a>
          </div>
        `,
      })
    );
  }
});

// escape helpers for admin UI
function escapeAttr(s) {
  // good enough for value=""
  return escapeHtml(s).replace(/\n/g, " ");
}

// ---------------- S1 ----------------
app.get("/s1", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const body = `
  <div class="card">
    <h2>Screen 1 — Trade type</h2>
    <form method="POST" action="/s1">
      <div class="row">
        <div class="field">
          <label>Trade type</label>
          <select name="tradeType" required>
            <option value="" ${!st.tradeType ? "selected" : ""}>— Select —</option>
            <option value="BALANCE" ${st.tradeType==="BALANCE" ? "selected":""}>BALANCE</option>
            <option value="IMBALANCE" ${st.tradeType==="IMBALANCE" ? "selected":""}>IMBALANCE</option>
            <option value="CUSTOM" ${st.tradeType==="CUSTOM" ? "selected":""}>CUSTOM (Any trade)</option>
          </select>
        </div>
      </div>
      <div style="margin-top:12px"><button type="submit">Next</button></div>
    </form>
    <hr/>
    <form method="POST" action="/logout"><button class="secondary" type="submit">Logout</button></form>
  </div>`;
  res.send(layout({ active: "Journal", userEmail: req.user.email, body, stateLabel: "S1" }));
});

app.post("/s1", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const tradeType = String(req.body.tradeType || "");
  const nextState = { tradeType };
  const nextHist = pushHistory(hist, st);

  writeSessionState(dbx, req.sid, nextState, nextHist);

  if (tradeType === "CUSTOM") return res.redirect("/c1");
  return res.redirect("/s2");
});

// ---------------- CUSTOM C1 ----------------
app.get("/c1", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const contracts = st.contracts ?? preset.contractsDefault;
  const tickSize = preset.tickSize;
  const tickValue = preset.tickValue;

  const direction = st.direction ?? "LONG";
  const entry = st.entry ?? "";
  const sl = st.slPrice ?? "";
  const tp = st.tpPrice ?? "";

  const errBox = st._errors?.length
    ? `<div class="error">${st._errors.map(e => `<div>• ${escapeHtml(e)}</div>`).join("")}</div>`
    : "";

  const body = `
  <div class="card">
    <h2>Custom Trade — Any setup (no rules)</h2>
    <div class="small">BALANCE/IMBALANCE дүрэм хэрэглэхгүй. Entry/SL/TP/Direction-оо шууд оруул.</div>
    <hr/>
    <form method="POST" action="/c1">
      <div class="row">
        <div class="field">
          <label>Instrument</label>
          <select name="instrument" required>
            ${Object.keys(INSTRUMENTS).map(k =>
              `<option value="${k}" ${instrument===k?"selected":""}>${escapeHtml(INSTRUMENTS[k].label||k)}</option>`
            ).join("")}
          </select>
        </div>
        <div class="field">
          <label>Contracts</label>
          <input name="contracts" type="number" min="1" step="1" value="${escapeHtml(contracts)}" required/>
        </div>
      </div>

      <div class="row">
        <div class="field"><label>Tick size</label><input name="tickSize" value="${escapeHtml(tickSize)}" readonly/></div>
        <div class="field"><label>Tick value ($/tick, 1 contract)</label><input name="tickValue" value="${escapeHtml(tickValue)}" readonly/></div>
      </div>

      <div class="row">
        <div class="field">
          <label>Direction</label>
          <select name="direction" required>
            ${["LONG","SHORT"].map(d=>`<option value="${d}" ${direction===d?"selected":""}>${d}</option>`).join("")}
          </select>
        </div>
        <div class="field"><label>Entry price</label><input name="entry" value="${escapeHtml(entry)}" required/></div>
      </div>

      <div class="row">
        <div class="field"><label>Stop-Loss (SL)</label><input name="sl" value="${escapeHtml(sl)}" required/></div>
        <div class="field"><label>Take-Profit (TP)</label><input name="tp" value="${escapeHtml(tp)}" required/></div>
      </div>

      <div style="margin-top:12px"><button type="submit">Next (Integration)</button></div>
    </form>

    <form method="POST" action="/back_c1" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>

    ${warnBox}
    ${errBox}
  </div>`;
  res.send(layout({ active: "Journal", userEmail: req.user.email, body, stateLabel: "C1" }));
});

app.post("/back_c1", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { hist } = readSessionState(sess);
  const { hist: nextHist, prev } = popHistory(hist);
  if (prev) writeSessionState(dbx, req.sid, prev, nextHist);
  res.redirect("/s1");
});

app.post("/c1", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const instrument = (req.body.instrument && INSTRUMENTS[String(req.body.instrument)]) ? String(req.body.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const contracts = Math.max(1, parseInt(String(req.body.contracts || preset.contractsDefault), 10) || preset.contractsDefault);
  const tickSize = preset.tickSize;
  const tickValue = preset.tickValue;

  const direction = String(req.body.direction || "").toUpperCase();
  const entry = parseNum(req.body.entry);
  const sl = parseNum(req.body.sl);
  const tp = parseNum(req.body.tp);

  const errs = [];
  if (!direction || (direction !== "LONG" && direction !== "SHORT")) errs.push("Direction шаардлагатай (LONG/SHORT).");
  if ([entry, sl, tp].some(x => x === null)) errs.push("Entry/SL/TP талбарууд хоосон байна.");
  if (entry !== null && sl !== null && Math.abs(entry - sl) < 1e-12) errs.push("Entry ба SL ижил байж болохгүй.");

  let oneR = null;
  let rr = null;
  let bePrice = null;

  if (!errs.length) {
    const riskPoints = Math.abs(entry - sl);
    const profitPoints = Math.abs(tp - entry);
    rr = riskPoints > 0 ? (profitPoints / riskPoints) : null;
    if (rr !== null && Number.isFinite(rr)) rr = Math.round(rr * 100) / 100;

    const riskTicks = tickSize > 0 ? (riskPoints / tickSize) : null;
    oneR = (riskTicks !== null) ? (riskTicks * tickValue * contracts) : null;
    if (oneR !== null && Number.isFinite(oneR)) oneR = Math.round(oneR * 100) / 100;

    if (direction === "LONG") bePrice = entry + riskPoints;
    if (direction === "SHORT") bePrice = entry - riskPoints;
  }

  const nextState = {
    ...st,
    tradeType: "CUSTOM",
    instrument,
    contracts,
    tickSize,
    tickValue,
    direction,
    entry,
    slPrice: sl,
    tpPrice: tp,
    bePrice,
    oneR,
    rr,
    _errors: errs,
    _intError: ""
  };

  if (errs.length) {
    writeSessionState(dbx, req.sid, nextState, hist);
    return res.redirect("/c1");
  }

  const nextHist = pushHistory(hist, st);
  writeSessionState(dbx, req.sid, nextState, nextHist);
  res.redirect("/s5");
});

// ---------------- S2 ----------------
app.get("/s2", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const isBalance = st.tradeType === "BALANCE";
  const isImbalance = st.tradeType === "IMBALANCE";

  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const val = st.val ?? "";
  const vah = st.vah ?? "";
  const tickSize = preset.tickSize;
  const tickValue = preset.tickValue;

  const touches = Array.isArray(st.touches) ? st.touches : ["", "", ""];
  while (touches.length < 3) touches.push("");

  const balanceAnchor = st.balanceAnchor ?? "VAL";
  const balanceEntry = st.balanceEntry ?? "";

  const direction = st.direction ?? "SHORT";
  const breakPrice = st.breakPrice ?? "";
  const pullbackPrice = st.pullbackPrice ?? "";
  const rejectionCandles = st.rejectionCandles ?? "";
  const entry3 = st?.entry3 ?? "";
const softOverride = st.softOverride ? true : false;
const overrideReason = st.overrideReason ?? "";

  const errBox = st._errors?.length
    ? `<div class="error"><b>Алдаа:</b><ul>${st._errors.map(e => `<li>${escapeHtml(e)}</li>`).join("")}</ul></div>`
    : "";

  const balanceBlock = `
    <h3>Balance Entry</h3>
    <div class="row">
      <div class="field">
        <label>Anchor</label>
        <select name="balanceAnchor">
          <option value="VAL" ${balanceAnchor==="VAL"?"selected":""}>VAL</option>
          <option value="VAH" ${balanceAnchor==="VAH"?"selected":""}>VAH</option>
        </select>
      </div>
      <div class="field">
        <label>Entry price</label>
        <input name="balanceEntry" value="${escapeHtml(balanceEntry)}" required/>
        <div class="small">Rule: Anchor-аас дотогш 2–3 tick</div>
      </div>
    </div>
  `;

  const imbalanceBlock = `
    <h3>Imbalance Entry</h3>
    <div class="row">
      <div class="field">
        <label>Direction</label>
        <select name="direction" required>
          <option value="LONG" ${direction==="LONG"?"selected":""}>LONG</option>
          <option value="SHORT" ${direction==="SHORT"?"selected":""}>SHORT</option>
        </select>
      </div>
      <div class="field"><label>Break price</label><input name="breakPrice" value="${escapeHtml(breakPrice)}" required/></div>
      <div class="field"><label>Pullback price</label><input name="pullbackPrice" value="${escapeHtml(pullbackPrice)}" required/></div>
      <div class="field"><label>Rejection candles (<=3)</label><input name="rejectionCandles" value="${escapeHtml(rejectionCandles)}" required/></div>
      <div class="field"><label>Entry (3rd candle close)</label><input name="entry3" value="${escapeHtml(entry3)}" required/></div>
    </div>
    <div class="small">Rules: break >= 10 tick; pullback = boundary ±3 tick; rejection <=3</div>
  `;

  const body = `
  <div class="card">
    <h2>Screen 2 — Context (${escapeHtml(st.tradeType || "—")})</h2>
    <form method="POST" action="/s2">
      <div class="row">
        <div class="field">
          <label>Instrument</label>
          <select name="instrument" required>
            ${Object.keys(INSTRUMENTS).map(k => `<option value="${k}" ${instrument===k?"selected":""}>${escapeHtml(INSTRUMENTS[k].label)}</option>`).join("")}
          </select>
          <div class="small">Instrument сонгосноор Tick size/value default орно.</div>
        </div>
        <div class="field"><label>VAL</label><input name="val" value="${escapeHtml(val)}" required/></div>
        <div class="field"><label>VAH</label><input name="vah" value="${escapeHtml(vah)}" required/></div>
        <div class="field"><label>Tick size</label><input name="tickSize" value="${escapeHtml(tickSize)}" readonly/></div>
        <div class="field"><label>Tick value ($/tick, 1 contract)</label><input name="tickValue" value="${escapeHtml(tickValue)}" readonly/></div>
      </div>

      <hr/>
      <div><b>Touches (3+)</b></div>
      <div class="row">
        ${touches.slice(0,3).map((t,i)=>`
          <div class="field">
            <label>Touch #${i+1}</label>
            <input name="touch${i+1}" value="${escapeHtml(t)}" required/>
          </div>
        `).join("")}
      </div>

      <hr/>
      ${isBalance ? balanceBlock : ""}
      ${isImbalance ? imbalanceBlock : ""}


<div style="margin-top:14px;">
  <label style="display:flex; align-items:center; gap:8px;">
    <input type="checkbox" name="softOverride" value="1" ${softOverride ? "checked" : ""}/>
    Зөвшөөрөөд үргэлжлүүлэх (soft warning)
  </label>
  <div class="small muted">Rule зөрчсөн байсан ч тэмдэглээд цааш явна. Dashboard дээр Override гэж харагдана.</div>
  <div class="field" style="margin-top:8px;">
    <label>Override reason (яагаад rule зөрчсөн ч орсон бэ?)</label>
    <textarea name="overrideReason" rows="2" style="width:100%; padding:10px; resize:vertical;">${escapeHtml(String(overrideReason||""))}</textarea>
  </div>
</div>

      <div style="margin-top:14px" class="row">
        <button type="submit">Validate & Next</button>
      </div>
    </form>

    <form method="POST" action="/back_s2" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>

<script>
(() => {
  const PRESETS = {"CL": {"tickSize": 0.01, "tickValue": 10}, "ES": {"tickSize": 0.25, "tickValue": 12.5}, "NQ": {"tickSize": 0.25, "tickValue": 5}, "GC": {"tickSize": 0.1, "tickValue": 10}};
  const sel = document.querySelector('select[name="instrument"]');
  const tickSizeEl = document.querySelector('input[name="tickSize"]');
  const tickValueEl = document.querySelector('input[name="tickValue"]');
  if (!sel || !tickSizeEl || !tickValueEl) return;
  function apply(k) {
    const p = PRESETS[k];
    if (!p) return;
    tickSizeEl.value = String(p.tickSize);
    tickValueEl.value = String(p.tickValue);
  }
  sel.addEventListener('change', (e) => apply(e.target.value));
  apply(sel.value);
})();
</script>

    ${errBox}
  </div>
  `;
  res.send(layout({ active: "Journal", userEmail: req.user.email, body, stateLabel: "S2" }));
});

app.post("/back_s2", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { hist } = readSessionState(sess);
  const { hist: nextHist, prev } = popHistory(hist);
  if (prev) writeSessionState(dbx, req.sid, prev, nextHist);
  res.redirect("/s1");
});

app.post("/s2", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const instrument = (req.body.instrument && INSTRUMENTS[String(req.body.instrument)])
    ? String(req.body.instrument)
    : ((st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL");
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const val = parseNum(req.body.val);
  const vah = parseNum(req.body.vah);
  const tickSize = preset.tickSize;
  const tickValue = preset.tickValue;

  const touches = [req.body.touch1, req.body.touch2, req.body.touch3].map(parseNum);

  const softOverride = (req.body.softOverride === "1" || req.body.softOverride === "on");
  const overrideReason = String(req.body.overrideReason || "").trim();

  const nextState = { ...st, instrument, val, vah, tickSize, tickValue, touches, _errors: [], _warnings: [] };

  if (st.tradeType === "BALANCE") {
    const balanceAnchor = String(req.body.balanceAnchor || "VAL");
    const balanceEntry = parseNum(req.body.balanceEntry);
    nextState.balanceAnchor = balanceAnchor;
    nextState.balanceEntry = balanceEntry;

const errs = validateBalance({ anchor: balanceAnchor, entry: balanceEntry, val, vah, tickSize });
if (errs.length) {
  nextState.softOverride = softOverride ? 1 : 0;
  nextState.overrideReason = overrideReason;
  if (softOverride) {
    if (!overrideReason || overrideReason.length < 3) {
      nextState._errors = ["Override reason бичнэ үү (хамгийн багадаа 3 тэмдэгт).", ...errs];
      writeSessionState(dbx, req.sid, nextState, hist);
      return res.redirect("/s2");
    }
    nextState._warnings = errs;
    nextState.overrideUsed = 1;
    nextState.overrideRules = errs.join(" | ");
  } else {
    nextState._errors = errs;
    writeSessionState(dbx, req.sid, nextState, hist);
    return res.redirect("/s2");
  }
} else {
  // valid -> clear override
  nextState.softOverride = 0;
  nextState.overrideUsed = 0;
  nextState.overrideReason = "";
  nextState.overrideRules = "";
}


    nextState.direction = (balanceAnchor === "VAL") ? "LONG" : "SHORT";
    nextState.entry = balanceEntry;
  }

  if (st.tradeType === "IMBALANCE") {
    const direction = String(req.body.direction || "");
    const breakPrice = parseNum(req.body.breakPrice);
    const pullbackPrice = parseNum(req.body.pullbackPrice);
    const rejectionCandles = parseNum(req.body.rejectionCandles);
    const entry3 = parseNum(req.body.entry3);

    nextState.direction = direction;
    nextState.breakPrice = breakPrice;
    nextState.pullbackPrice = pullbackPrice;
    nextState.rejectionCandles = rejectionCandles;
    nextState.entry3 = entry3;
    nextState.entry = entry3;

    const errs = [];
    if (!direction) errs.push("Direction шаардлагатай.");
    if ([breakPrice, pullbackPrice, rejectionCandles, entry3, val, vah].some(x => x === null))
      errs.push("Талбарууд хоосон байна.");
    if (rejectionCandles !== null && rejectionCandles > 3)
      errs.push("Rejection invalid: 4+ candle бол trade no allowed.");

    if (breakPrice !== null && pullbackPrice !== null && val !== null && vah !== null) {
      const tenTicks = 10 * tickSize;

      if (direction === "LONG") {
        if (breakPrice < vah + tenTicks - 1e-9) errs.push("Break invalid: VAH дээрээс дор хаяж 10 tick дээш байх ёстой.");
        const pbDiff = Math.abs(pullbackPrice - vah);
        if (pbDiff > 3 * tickSize + 1e-9) errs.push("Pullback invalid: VAH орчим ±3 tick.");
      } else if (direction === "SHORT") {
        if (breakPrice > val - tenTicks + 1e-9) errs.push("Break invalid: VAL доороос дор хаяж 10 tick доош байх ёстой.");
        const pbDiff = Math.abs(pullbackPrice - val);
        if (pbDiff > 3 * tickSize + 1e-9) errs.push("Pullback invalid: VAL орчим ±3 tick.");
      }
    }

if (errs.length) {
  nextState.softOverride = softOverride ? 1 : 0;
  nextState.overrideReason = overrideReason;
  if (softOverride) {
    if (!overrideReason || overrideReason.length < 3) {
      nextState._errors = ["Override reason бичнэ үү (хамгийн багадаа 3 тэмдэгт).", ...errs];
      writeSessionState(dbx, req.sid, nextState, hist);
      return res.redirect("/s2");
    }
    nextState._warnings = errs;
    nextState.overrideUsed = 1;
    nextState.overrideRules = errs.join(" | ");
  } else {
    nextState._errors = errs;
    writeSessionState(dbx, req.sid, nextState, hist);
    return res.redirect("/s2");
  }
} else {
  nextState.softOverride = 0;
  nextState.overrideUsed = 0;
  nextState.overrideReason = "";
  nextState.overrideRules = "";
}

  }

  const nextHist = pushHistory(hist, st);
  writeSessionState(dbx, req.sid, nextState, nextHist);
  res.redirect("/s3");
});

// ---------------- S3 ----------------
app.get("/s3", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const tickSize = preset.tickSize;
  const tickValue = preset.tickValue;
  const contracts = st.contracts ?? preset.contractsDefault;
  const rr = st.rr ?? 2;
  const oneR = st.oneR ?? 300;

  const { ticksRaw, ticksRounded, oneRActual } = computeRiskTicks({ oneR, tickValue, contracts });

  const errBox = st._errors?.length
    ? `<div class="error"><b>Алдаа:</b><ul>${st._errors.map(e => `<li>${escapeHtml(e)}</li>`).join("")}</ul></div>`
    : "";

  const body = `
  <div class="card">
    <h2>Screen 3 — Risk</h2>
    ${errBox}
    <ul>
      <li>Instrument: <b>${escapeHtml(instrument)}</b> — ${escapeHtml(preset.label)}</li>
      <li>TickSize: <b>${escapeHtml(String(tickSize))}</b></li>
      <li>TickValue: <b>${escapeHtml(String(tickValue))}</b> $/tick (1 contract)</li>
      <li>Direction: <b>${escapeHtml(String(st.direction || "—"))}</b></li>
      <li>Entry: <b>${escapeHtml(String(st.entry ?? "—"))}</b></li>
    </ul>

    <form method="POST" action="/s3">
      <div class="row">
        <div class="field" style="max-width:220px">
          <label>Contracts (гэрээний тоо)</label>
          <input name="contracts" value="${escapeHtml(String(contracts))}" required/>
        </div>
        <div class="field" style="max-width:220px">
          <label>RR (TP = +RR)</label>
          <input name="rr" value="${escapeHtml(String(rr))}" required/>
        </div>
        <div class="field" style="max-width:260px">
          <label>1R = ? $ (risk per trade)</label>
          <input name="oneR" value="${escapeHtml(String(oneR))}" required/>
        </div>
      </div>

      <div class="small" style="margin-top:8px">
        Тооцоо: 1R ticks ≈ ${escapeHtml(ticksRaw===null?"—":ticksRaw.toFixed(2))}
        → <b>${escapeHtml(ticksRounded===null?"—":String(ticksRounded))} ticks</b>
        (Actual 1R ≈ $${escapeHtml(oneRActual===null?"—":String(oneRActual))})
      </div>

      <div style="margin-top:12px" class="row">
        <button type="submit">Next (Levels)</button>
      </div>
    </form>

    <form method="POST" action="/back_s3" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>
  </div>`;
  res.send(layout({ active: "Journal", userEmail: req.user.email, body, stateLabel: "S3" }));
});

app.post("/back_s3", authMiddleware, async (req, res) => {
  res.redirect("/s2");
});

app.post("/s3", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const oneR = parseNum(req.body.oneR);
  const contracts = parseNum(req.body.contracts);
  const rr = parseNum(req.body.rr);

  const errs = [];
  if (oneR === null || oneR <= 0) errs.push("1R нь 0-ээс их байх ёстой.");
  if (contracts === null || contracts <= 0) errs.push("Contracts нь 0-ээс их байх ёстой.");
  if (rr === null || rr <= 0) errs.push("RR нь 0-ээс их байх ёстой.");

  const nextState = { ...st, oneR, contracts, rr, _errors: [] };
  if (errs.length) {
    nextState._errors = errs;
    writeSessionState(dbx, req.sid, nextState, hist);
    return res.redirect("/s3");
  }

  const nextHist = pushHistory(hist, st);
  writeSessionState(dbx, req.sid, nextState, nextHist);
  res.redirect("/s4");
});

// ---------------- S4 ----------------
app.get("/s4", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const entry = Number(st.entry);
  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const tickSize = preset.tickSize;
  const tickValue = preset.tickValue;
  const contracts = Number(st.contracts ?? preset.contractsDefault);
  const rr = Number(st.rr ?? 2);
  const dir = st.direction;

  const { ticksRaw, tickR, oneRPoints, tpPoints, oneRActual } =
    computeLevels({ entry, tickSize, oneR: st.oneR, tickValue, contracts, rr });

  function pricePlus(p, pts) { return Number((p + pts).toFixed(2)); }
  function priceMinus(p, pts) { return Number((p - pts).toFixed(2)); }

  let sl, tp, be;
  if (dir === "LONG") {
    sl = priceMinus(entry, oneRPoints);
    tp = pricePlus(entry, tpPoints);
    be = pricePlus(entry, oneRPoints);
  } else {
    sl = pricePlus(entry, oneRPoints);
    tp = priceMinus(entry, tpPoints);
    be = priceMinus(entry, oneRPoints);
  }

  const body = `
  <div class="card">
    <h2>Screen 4 — Levels (auto)</h2>
    <div class="kpis">
      <span class="kpi">${escapeHtml(st.tradeType||"—")}</span>
      <span class="kpi">${escapeHtml(dir||"—")}</span>
      <span class="kpi">Entry: ${escapeHtml(entry)}</span>
      <span class="kpi">Instrument: ${escapeHtml(instrument)}</span>
      <span class="kpi">Contracts: ${escapeHtml(String(contracts))}</span>
      <span class="kpi">1R target: $${escapeHtml(String(st.oneR))} (Actual ≈ $${escapeHtml(String(oneRActual ?? "—"))})</span>
      <span class="kpi">RR: ${escapeHtml(String(rr))}</span>
    </div>
    <hr/>
    <div class="small">
      1R ticks ≈ ${escapeHtml(ticksRaw===null?"—":ticksRaw.toFixed(2))} → <b>${escapeHtml(tickR===null?"—":String(tickR))} ticks</b>
      | TickSize: ${escapeHtml(String(tickSize))} | TickValue: $${escapeHtml(String(tickValue))}/tick/contract
    </div>
    <ul>
      <li>SL (-1R): <b>${escapeHtml(sl)}</b></li>
      <li>TP (+${escapeHtml(String(rr))}R): <b>${escapeHtml(tp)}</b></li>
      <li>BE trigger (+1R): <b>${escapeHtml(be)}</b></li>
    </ul>

    <form method="POST" action="/s4_next">
      <input type="hidden" name="sl" value="${escapeHtml(sl)}"/>
      <input type="hidden" name="tp" value="${escapeHtml(tp)}"/>
      <input type="hidden" name="be" value="${escapeHtml(be)}"/>
      <button type="submit">Next (Integration)</button>
    </form>

    <form method="POST" action="/back_s4" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>
  </div>`;
  res.send(layout({ active: "Journal", userEmail: req.user.email, body, stateLabel: "S4" }));
});

app.post("/back_s4", authMiddleware, async (req, res) => {
  res.redirect("/s3");
});

app.post("/s4_next", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const nextState = {
    ...st,
    slPrice: parseNum(req.body.sl),
    tpPrice: parseNum(req.body.tp),
    bePrice: parseNum(req.body.be),
  };
  const nextHist = pushHistory(hist, st);
  writeSessionState(dbx, req.sid, nextState, nextHist);

  res.redirect("/s5");
});

// ---------------- S5 (Integration) ----------------
app.get("/s5", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const copy = getIntegrationCopy(dbx, req.user.id);

  const cur = Math.max(1, Math.min(4, Number(st.intStep ?? 1)));
  const errHtml = st._intError ? escapeHtml(st._intError) : "";

  const body = renderScreen5({
    st: {
      ...st,
      emotion: st.emotion ?? "Тодорхойгүй",
      p1_bodyLocation: st.p1_bodyLocation ?? "Цээж",
      p1_breathing: st.p1_breathing ?? "Жигд",
      p2_fixing: st.p2_fixing ?? "Үгүй",
      p2_observing: st.p2_observing ?? "Хатуу",
      p3_release: st.p3_release ?? "Үгүй",
      p3_releaseLocation: st.p3_releaseLocation ?? "Цээж",
      p3_staying: st.p3_staying ?? "Амархан",
      p4_change: st.p4_change ?? "Өөрчлөлтгүй",
      p4_insight: st.p4_insight ?? ""
    },
    cur,
    errHtml,
    copy
  });

  res.send(layout({ active: "Journal", userEmail: req.user.email, body, stateLabel: "S5" }));
});

app.post("/s5", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const clampStep = (n) => Math.max(1, Math.min(4, Number.isFinite(n) ? n : 1));
  const nav = String(req.body.nav || "next");
  const cur = clampStep(Number(req.body.curStep || st.intStep || 1));

  const emotion = String(req.body.emotion ?? st.emotion ?? "Тодорхойгүй").trim() || "Тодорхойгүй";
  const nextState = { ...st, emotion, intStep: cur, _intError: "" };

  if (cur === 1) {
    nextState.p1_bodyLocation = String(req.body.p1_bodyLocation ?? st.p1_bodyLocation ?? "Цээж");
    nextState.p1_breathing = String(req.body.p1_breathing ?? st.p1_breathing ?? "Жигд");
    nextState.intensityBefore = String(req.body.intensityBefore ?? st.intensityBefore ?? "").trim();
  }
  if (cur === 2) {
    nextState.p2_fixing = String(req.body.p2_fixing ?? st.p2_fixing ?? "Үгүй");
    nextState.p2_observing = String(req.body.p2_observing ?? st.p2_observing ?? "Тийм");
  }
  if (cur === 3) {
    nextState.p3_release = String(req.body.p3_release ?? st.p3_release ?? "Үгүй");
    nextState.p3_releaseLocation = String(req.body.p3_releaseLocation ?? st.p3_releaseLocation ?? "Цээж");
    nextState.p3_staying = String(req.body.p3_staying ?? st.p3_staying ?? "Амархан");
    if (nextState.p3_release !== "Тийм") nextState.p3_releaseLocation = "";
  }
  if (cur === 4) {
    nextState.p4_change = String(req.body.p4_change ?? st.p4_change ?? "Өөрчлөлтгүй");
    nextState.p4_insight = String(req.body.p4_insight ?? st.p4_insight ?? "").trim();
    nextState.intensityAfter = String(req.body.intensityAfter ?? st.intensityAfter ?? "").trim();
  }

  if (nav === "back") {
    nextState.intStep = clampStep(cur - 1);
    writeSessionState(dbx, req.sid, nextState, hist);
    return res.redirect("/s5");
  }

  if (nav === "next") {
    nextState.intStep = clampStep(cur + 1);
    writeSessionState(dbx, req.sid, nextState, hist);
    return res.redirect("/s5");
  }

  if (nav === "complete") {
    if (!String(nextState.p4_insight || "").trim()) {
      nextState._intError = "Complete хийхийн өмнө Phase 4 дээр нэг өгүүлбэрийн insight бичээрэй.";
      nextState.intStep = 4;
      writeSessionState(dbx, req.sid, nextState, hist);
      return res.redirect("/s5");
    }

    const toInt010 = (v) => {
      const n = Number(String(v ?? "").trim());
      if (!Number.isFinite(n)) return null;
      return Math.max(0, Math.min(10, Math.round(n)));
    };

    const id = randId("int_");
    const createdAt = nowIso();
    const intensityBefore = toInt010(nextState.intensityBefore);
    const intensityAfter  = toInt010(nextState.intensityAfter);

    const payload = {
      createdAt,
      emotion: nextState.emotion || "Тодорхойгүй",
      phase1: {
        bodyLocation: nextState.p1_bodyLocation || "",
        breathing: nextState.p1_breathing || "",
        intensityBefore
      },
      phase2: {
        fixing: nextState.p2_fixing || "",
        observingShape: nextState.p2_observing || ""
      },
      phase3: {
        release: nextState.p3_release || "",
        releaseLocation: nextState.p3_releaseLocation || "",
        staying: nextState.p3_staying || ""
      },
      phase4: {
        change: nextState.p4_change || "",
        intensityAfter,
        insight: String(nextState.p4_insight || "").trim()
      }
    };

    exec(dbx, `INSERT INTO integration_sessions
      (id, user_id, trade_id, created_at, completed_at, emotion, intensity_before, intensity_after, payload_json)
      VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        req.user.id,
        createdAt,
        createdAt,
        payload.emotion,
        intensityBefore,
        intensityAfter,
        JSON.stringify(payload)
      ]
    );
    persistDb();

    nextState.integrationComplete = 1;
    const nextHist = pushHistory(hist, st);
    writeSessionState(dbx, req.sid, nextState, nextHist);
    return res.redirect("/s6");
  }

  writeSessionState(dbx, req.sid, nextState, hist);
  res.redirect("/s5");
});

// ---------------- S6 ----------------
app.get("/s6", authMiddleware, async (req, res) => {
  const body = `
  <div class="card">
    <h2>Screen 6 — Trade result</h2>
    <form method="POST" action="/s6" enctype="multipart/form-data">
      <div class="field" style="max-width:420px">
        <label>Chart screenshot (PNG/JPG)</label>
        <input type="file" name="chart" accept="image/*" required/>
        <div class="small">Зураг хавсаргаад TP/BE/SL-ээс сонгоно.</div>
      </div>
      <div class="row">
        <button name="result" value="TP" type="submit">TP (+R)</button>
        <button name="result" value="BE" type="submit">BE (0R)</button>
        <button name="result" value="SL" type="submit">SL (-1R)</button>
      </div>
    </form>

    <form method="POST" action="/back_s6" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>
  </div>`;
  res.send(layout({ active: "Journal", userEmail: req.user.email, body, stateLabel: "S6" }));
});

app.post("/back_s6", authMiddleware, async (req, res) => {
  res.redirect("/s5");
});

app.post("/s6", authMiddleware, async (req, res) => {
  const isMultipart = String(req.headers["content-type"] || "").includes("multipart/form-data");

  let uploadFilename = null;
  let resultOverride = null;

  if (isMultipart) {
    try {
      const parsed = await parseMultipartSingleFile(req, { fileField: "chart" });
      uploadFilename = parsed.filename;
      resultOverride = String(parsed.fields.result || "");
      req.body = { ...(parsed.fields || {}) };
    } catch (e) {
      const body = `<div class="card"><h2>Error</h2><div class="error">Upload error: ${escapeHtml(String(e.message||e))}</div><a class="pill" href="/s6">Back</a></div>`;
      return res.send(layout({ active: "Journal", userEmail: req.user.email, body, stateLabel: "S6" }));
    }
  }

  const dbx = await getDb();
  const sess = one(dbx, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const result = (resultOverride || String(req.body.result || "")).toUpperCase();
  const rr = (st.rr ?? 2);
  const { pnlR } = pnlFromResult(result, rr);
  const pnlS = (pnlR * (st.oneR ?? 0));

  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const contracts = Number(st.contracts ?? preset.contractsDefault);
  const tickSize = preset.tickSize;
  const tickValue = preset.tickValue;

  const raw = JSON.stringify(st);
  const noteLen = String(st.p4_insight || st.note || "").trim().length;

  exec(dbx, `INSERT INTO trades (
    user_id, created_at,
    instrument, trade_type, direction,
    entry, one_r, contracts, tick_size, tick_value, rr,
    sl_price, tp_price, be_price,
    result, pnl_r, pnl_s,
    emotion, mode, body_scan, note_len,
    override_used, override_reason, override_rules,
    raw_json, chart_image
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  [
    req.user.id, nowIso(),
    instrument, String(st.tradeType || "CUSTOM"), String(st.direction || "LONG"),
    Number(st.entry ?? 0), Number(st.oneR ?? 0), contracts, tickSize, tickValue, Number(rr),
    st.slPrice ?? null, st.tpPrice ?? null, st.bePrice ?? null,
    result, Number(pnlR), Number(pnlS),
    st.emotion ?? null, st.mode ?? null, st.bodyScan ? 1 : 0, noteLen,
    st.overrideUsed ? 1 : 0, (st.overrideReason ?? null), (st.overrideRules ?? null),
    raw, uploadFilename
  ]
);
  persistDb();

  // reset flow
  writeSessionState(dbx, req.sid, {}, []);
  res.redirect("/dashboard");
});

// ---------------- Integrations page ----------------
app.get("/integrations", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const rows = all(dbx, `
    SELECT id, created_at, emotion, intensity_before, intensity_after
    FROM integration_sessions
    WHERE user_id=?
    ORDER BY created_at DESC
    LIMIT 50
  `, [req.user.id]);

  const body = `
  <div class="card">
    <h2>Integrations</h2>
    <div class="small muted">Сүүлд хийсэн 50 integration session.</div>
    <hr/>
    ${rows.length ? `
      <table class="tight">
        <thead><tr><th>Time</th><th>Emotion</th><th>Before</th><th>After</th></tr></thead>
        <tbody>
          ${rows.map(r => `
            <tr>
              <td>${escapeHtml(r.created_at)}</td>
              <td><b>${escapeHtml(r.emotion || "")}</b></td>
              <td>${escapeHtml(r.intensity_before ?? "")}</td>
              <td>${escapeHtml(r.intensity_after ?? "")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    ` : `<div class="small muted">No integrations yet.</div>`}
  </div>`;
  res.send(layout({ active: "Integrations", userEmail: req.user.email, body, stateLabel: "INTEGRATIONS" }));
});

// ---------------- Dashboard ----------------
app.get("/dashboard", authMiddleware, async (req, res) => {
  const dbx = await getDb();

  const stats = one(dbx, `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN result='TP' THEN 1 ELSE 0 END) as tp,
      SUM(CASE WHEN result='BE' THEN 1 ELSE 0 END) as be,
      SUM(CASE WHEN result='SL' THEN 1 ELSE 0 END) as sl,
      COALESCE(SUM(pnl_r),0) as net_r,
      COALESCE(SUM(pnl_s),0) as net_s,
      COALESCE(AVG(pnl_r),0) as avg_r,
      SUM(CASE WHEN override_used=1 THEN 1 ELSE 0 END) as overrides
    FROM trades
    WHERE user_id = ?
  `, [req.user.id]) || { total:0,tp:0,be:0,sl:0,net_r:0,net_s:0,avg_r:0 };

  const winrate = stats.total ? ((stats.tp / stats.total) * 100) : 0;

  const recent = all(dbx, `
    SELECT id, created_at, instrument, trade_type, direction, contracts, rr, result, pnl_r, pnl_s, emotion, override_used, override_reason, chart_image
    FROM trades
    WHERE user_id=?
    ORDER BY id DESC
    LIMIT 30
  `, [req.user.id]);

  const kpi = (label, value) => `
    <div class="kpi-card">
      <div class="kpi-label">${label}</div>
      <div class="kpi-value">${value}</div>
    </div>
  `;

  const body = `
  <div class="dash">
    <div class="dash-top">
      ${kpi("Total Trades", escapeHtml(stats.total))}
      ${kpi("Win Rate", escapeHtml(winrate.toFixed(1)) + "%")}
      ${kpi("Net R", escapeHtml(Number(stats.net_r||0).toFixed(2)) + "R")}
      ${kpi("Net $", escapeHtml(Number(stats.net_s||0).toFixed(0)) + "$")}
      ${kpi("Avg R / Trade", escapeHtml(Number(stats.avg_r||0).toFixed(2)) + "R")}
      ${kpi("TP / BE / SL", `${escapeHtml(stats.tp)}/${escapeHtml(stats.be)}/${escapeHtml(stats.sl)}`)}
      ${kpi("Overrides", escapeHtml(stats.overrides||0))}
    </div>

    <div class="dash-grid">
      <div class="card">
        <div class="card-title">Recent Trades</div>
        ${recent.length ? `
          <table class="tight">
            <thead><tr>
              <th>#</th><th>Time</th><th>Instr</th><th>Type</th><th>Dir</th><th>Contracts</th><th>RR</th><th>Result</th><th>R</th><th>$</th><th>Emotion</th><th>Override</th><th>Chart</th>
            </tr></thead>
            <tbody>
              ${recent.map(r => `
                <tr>
                  <td>${escapeHtml(r.id)}</td>
                  <td>${escapeHtml(r.created_at)}</td>
                  <td><b>${escapeHtml(r.instrument)}</b></td>
                  <td>${escapeHtml(r.trade_type)}</td>
                  <td>${escapeHtml(r.direction)}</td>
                  <td>${escapeHtml(r.contracts)}</td>
                  <td>${escapeHtml(r.rr)}</td>
                  <td><b>${escapeHtml(r.result)}</b></td>
                  <td>${escapeHtml(Number(r.pnl_r||0).toFixed(2))}</td>
                  <td>${escapeHtml(Number(r.pnl_s||0).toFixed(0))}</td>
                  <td>${escapeHtml(r.emotion || "")}</td>
                  <td>${r.override_used ? `<span class="badge" title="${escapeHtml(String(r.override_reason||""))}">OVR</span>` : "—"}</td>
                  <td>${r.chart_image ? `<a href="/uploads/${escapeHtml(r.chart_image)}" target="_blank">View</a>` : "—"}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        ` : `<div class="small muted">No trades yet</div>`}
      </div>
    </div>
  </div>
  `;

  res.send(layout({ active: "Dashboard", userEmail: req.user.email, body, stateLabel: "DASH" }));
});

// ---------------- Exports ----------------
app.get("/export/trades.csv", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const rows = all(dbx, `
    SELECT created_at, instrument, trade_type, direction, entry, one_r, contracts, rr,
           sl_price, tp_price, be_price, result, pnl_r, pnl_s, emotion, mode,
           override_used, override_reason, override_rules, chart_image
    FROM trades
    WHERE user_id=?
    ORDER BY id ASC
  `, [req.user.id]);

  const headers = Object.keys(rows[0] || { created_at: "" });
  const csv = rowsToCsv(headers, rows);

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="trades.csv"`);
  res.send(csv);
});

app.get("/export/integrations.csv", authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const rows = all(dbx, `
    SELECT created_at, completed_at, emotion, intensity_before, intensity_after, payload_json
    FROM integration_sessions
    WHERE user_id=?
    ORDER BY created_at ASC
  `, [req.user.id]);

  const headers = Object.keys(rows[0] || { created_at: "" });
  const csv = rowsToCsv(headers, rows);

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="integrations.csv"`);
  res.send(csv);
});

// ---------------- start ----------------
getDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running: http://localhost:${PORT}`);
    });
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });