const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");
const { renderScreen5, DEFAULT_COPY } = require("./views/screen5");
const initSqlJs = require("sql.js");

const bcrypt = require("bcryptjs");
const APP_TITLE = "PHASE 2 — Journal + Dashboard v75-pro+custom";
const DB_FILE = path.join(__dirname, "data.sqlite");
const SQL_WASM_FILE = path.join(__dirname, "node_modules", "sql.js", "dist", "sql-wasm.wasm");

const PORT = process.env.PORT || 3000;

const app = express();
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use("/public", express.static(path.join(__dirname, "public")));

const UPLOAD_DIR = path.join(__dirname, 'uploads');
try { if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch (_) {}
app.use('/uploads', express.static(UPLOAD_DIR));

// ---- Instruments (presets) ----
// Extend later if you want (YM, RTY, 6E, SI, etc.)
const INSTRUMENTS = {
  CL: { label: "CL — Crude Oil", tickSize: 0.01, tickValue: 10, contractsDefault: 2 },
  ES: { label: "ES — S&P 500", tickSize: 0.25, tickValue: 12.5, contractsDefault: 1 },
  NQ: { label: "NQ — Nasdaq", tickSize: 0.25, tickValue: 5, contractsDefault: 1 },
  GC: { label: "GC — Gold", tickSize: 0.1, tickValue: 10, contractsDefault: 1 },
};

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Backwards-compatible alias used in some view builders
function esc(s) {
  return escapeHtml(s);
}


function nowIso() {
  return new Date().toISOString();
}

function safeJsonParse(s, fallback) {
  try {
    const v = JSON.parse(String(s));
    return (v && typeof v === 'object') ? v : fallback;
  } catch (_) {
    return fallback;
  }
}

function getIntegrationCopy(db, userId) {
  const row = one(db, `SELECT payload_json FROM integration_texts WHERE user_id=?`, [userId]);
  const saved = row && row.payload_json ? safeJsonParse(row.payload_json, {}) : {};
  // Merge defaults -> saved overrides
  return { ...DEFAULT_COPY, ...saved };
}

function saveIntegrationCopy(db, userId, copyObj) {
  const payload = JSON.stringify(copyObj || {});
  // Upsert
  exec(db, `INSERT INTO integration_texts (user_id, payload_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET payload_json=excluded.payload_json, updated_at=excluded.updated_at;`,
      [userId, payload, nowIso()]);
  persistDb();
}

function resetIntegrationCopy(db, userId) {
  exec(db, `DELETE FROM integration_texts WHERE user_id=?`, [userId]);
  persistDb();
}

function csvEscape(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  if (/[\",\n\r]/.test(s)) return '"' + s.replaceAll('"', '""') + '"';
  return s;
}

function rowsToCsv(headers, rows) {
  const lines = [];
  lines.push(headers.map(csvEscape).join(','));
  for (const r of rows) {
    lines.push(headers.map(h => csvEscape(r[h])).join(','));
  }
  return lines.join('\n');
}

function randId(prefix="") {
  return prefix + Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2);
}

let SQL;
let db;

async function getDb() {
  if (db) return db;
  SQL = await initSqlJs({ locateFile: (file) => (file === "sql-wasm.wasm" ? SQL_WASM_FILE : file) });
  if (fs.existsSync(DB_FILE)) {
    const buf = fs.readFileSync(DB_FILE);
    db = new SQL.Database(new Uint8Array(buf));
  } else {
    db = new SQL.Database();
  }
  ensureSchema(db);
  upgradeLegacyPasswords(db);
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
function exec(db, sql, params=[]) {
  const stmt = db.prepare(sql);
  stmt.bind(normalizeParams(params));
  while (stmt.step()) { /* ignore */ }
  stmt.free();
}

function one(db, sql, params=[]) {
  const stmt = db.prepare(sql);
  stmt.bind(normalizeParams(params));
  const row = stmt.step() ? stmt.getAsObject() : null;
  stmt.free();
  return row;
}

function all(db, sql, params=[]) {
  const stmt = db.prepare(sql);
  stmt.bind(normalizeParams(params));
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ===== Global text overrides cache (per user) =====
// Keeps overrides in memory to allow applying them transparently in a
// synchronous res.send wrapper.
const TEXT_OVERRIDE_CACHE = new Map(); // user_id -> Array<{from_text,to_text}>

function loadTextOverridesForUser(db, user_id) {
  if (!user_id) return [];
  try {
    if (!hasTable(db, 'text_overrides')) return [];
    const rows = all(db, `SELECT from_text, to_text FROM text_overrides WHERE user_id=? ORDER BY updated_at DESC`, [user_id]);
    const cleaned = (rows || []).filter(r => r && r.from_text && (r.to_text !== undefined));
    TEXT_OVERRIDE_CACHE.set(user_id, cleaned);
    return cleaned;
  } catch (_) {
    return [];
  }
}

function applyTextOverrides(html, overrides) {
  let out = String(html ?? "");
  if (!Array.isArray(overrides) || overrides.length === 0) return out;
  // Replace in deterministic order (longer "from" first reduces accidental partial matches)
  const rows = [...overrides].sort((a,b)=> String(b.from_text||"").length - String(a.from_text||"").length);
  for (const r of rows) {
    const from = String(r.from_text ?? "");
    const to = String(r.to_text ?? "");
    if (!from) continue;
    if (from === to) continue;
    out = out.split(from).join(to);
  }
  return out;
}

function applyTextOverrides(html, overrides) {
function hasColumn(db, table, col) {
  const rows = all(db, `PRAGMA table_info(${table})`);
  return rows.some(r => r.name === col);
}

function hasTable(db, table) {
  const r = one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", [table]);
  return !!(r && r.name);
}

function ensureSchema(db){
  // --- Minimal schema migration (when user keeps an old data.sqlite) ---
  // Older builds used different session columns (e.g., token) and will crash
  // when the app tries to write the new columns (e.g., sid/state_json).
  const colsOf = (table) => {
    try {
      const r = db.exec(`PRAGMA table_info(${table});`);
      if (!r || !r[0] || !Array.isArray(r[0].values)) return [];
      return r[0].values.map(v => String(v[1])); // column name is 2nd field
    } catch (_) {
      return [];
    }
  };
  const hasCol = (table, col) => colsOf(table).includes(col);

  // If an old sessions table exists, rebuild it to the new shape.
  if (hasTable(db, 'sessions') && !hasCol('sessions', 'sid')) {
    exec(db, 'DROP TABLE sessions;');
  }

  // Core tables (idempotent)
  exec(db, `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );`);

  // Session store (single active session per browser cookie sid)
  exec(db, `CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    state_json TEXT,
    history_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );`);

  exec(db, `CREATE TABLE IF NOT EXISTS trades (
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

  exec(db, `CREATE TABLE IF NOT EXISTS integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    emotion TEXT NOT NULL,
    mode TEXT NOT NULL,
    body_scan INTEGER NOT NULL,
    note TEXT NOT NULL
  );`);
  // Integration sessions (v2) - rich payload for review
  exec(db, `CREATE TABLE IF NOT EXISTS integration_sessions (
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
  exec(db, `CREATE INDEX IF NOT EXISTS idx_integration_sessions_user_created ON integration_sessions(user_id, created_at);`);
  exec(db, `CREATE INDEX IF NOT EXISTS idx_integration_sessions_trade ON integration_sessions(trade_id);`);

  // Editable integration copy (per user)
  exec(db, `CREATE TABLE IF NOT EXISTS integration_texts (
    user_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );`);

  // ===== TEXT OVERRIDES (Admin editable texts across the whole app) =====
  // This is a global, per-user replacement map. "from_text" must match exactly
  // what appears in rendered HTML (including spacing/punctuation/case).
  exec(db, `CREATE TABLE IF NOT EXISTS text_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    from_text TEXT NOT NULL,
    to_text TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, from_text)
  );`);
  exec(db, `CREATE INDEX IF NOT EXISTS idx_text_overrides_user ON text_overrides(user_id);`);


  // ---- Legacy DB migrations (safe) ----

  // 0) sessions table from older builds (token-based) -> rebuild to sid-based
  if (hasTable(db, "sessions") && !hasColumn(db, "sessions", "sid")) {
    exec(db, `ALTER TABLE sessions RENAME TO sessions_legacy;`);
    exec(db, `CREATE TABLE sessions (
      sid TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      state_json TEXT NOT NULL,
      history_json TEXT NOT NULL
    );`);
    // We intentionally do NOT migrate legacy session rows.
    // (Different format, and users can just login again.)
    exec(db, `DROP TABLE sessions_legacy;`);
  }

  // 0.1) trades table from older builds missing user_id -> rebuild
  if (hasTable(db, "trades") && !hasColumn(db, "trades", "user_id")) {
    exec(db, `ALTER TABLE trades RENAME TO trades_legacy;`);
    exec(db, `CREATE TABLE trades (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      instrument TEXT NOT NULL,
      trade_type TEXT NOT NULL,
      direction TEXT NOT NULL,
      entry REAL NOT NULL,
      contracts INTEGER NOT NULL,
      tick_size REAL NOT NULL,
      tick_value REAL NOT NULL,
      risk_1r REAL NOT NULL,
      result TEXT NOT NULL,
      pnl_r REAL NOT NULL,
      pnl_dollar REAL NOT NULL,
      raw_json TEXT
    );`);
    // Legacy trades can't be safely assigned to a user.
    // Keeping the old table for manual recovery if needed.
  }

  // 0.2) integrations table from older builds missing user_id -> rebuild
  if (hasTable(db, "integrations") && !hasColumn(db, "integrations", "user_id")) {
    exec(db, `ALTER TABLE integrations RENAME TO integrations_legacy;`);
    exec(db, `CREATE TABLE integrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      emotion TEXT NOT NULL,
      mode TEXT NOT NULL,
      body_scan INTEGER NOT NULL,
      note TEXT NOT NULL
    );`);
  }

  // 1) users table without id / wrong schema
  if (hasTable(db, "users") && !hasColumn(db, "users", "id")) {
    // Rebuild users table with proper schema
    exec(db, `ALTER TABLE users RENAME TO users_legacy;`);
    exec(db, `CREATE TABLE users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );`);
    const legacy = all(db, `SELECT * FROM users_legacy;`, []);
    for (const r of legacy) {
      const email = String(r.email || "").trim().toLowerCase();
      if (!email) continue;
      const ph = String(r.password_hash || r.password || "");
      const createdAt = String(r.created_at || nowIso());
      // NOTE: id is generated; legacy passwords may be plain and will be upgraded later.
      exec(db, `INSERT OR IGNORE INTO users (id,email,password_hash,created_at) VALUES (?,?,?,?);`,
        [randId('u_'), email, ph || "", createdAt]);
    }
    exec(db, `DROP TABLE users_legacy;`);
  }

  // 2) trades missing user_id/trade_type/raw_json (older versions)
  if (hasTable(db, "trades")) {
    const cols = [
      ["user_id", "TEXT"],
      ["trade_type", "TEXT"],
      ["raw_json", "TEXT"],
      ["one_r", "REAL"],
      ["pnl_s", "REAL"],
      ["chart_image", "TEXT"],
      ["emotion", "TEXT"],
      ["mode", "TEXT"],
      ["body_scan", "INTEGER"],
      ["note_len", "INTEGER"]
    ];
    for (const [c, t] of cols) {
      if (!hasColumn(db, "trades", c)) {
        try { exec(db, `ALTER TABLE trades ADD COLUMN ${c} ${t};`); } catch(e) {}
      }
    }
    // Backfill user_id for existing rows
    if (hasColumn(db, "trades", "user_id")) {
      exec(db, `UPDATE trades SET user_id = COALESCE(user_id,'legacy') WHERE user_id IS NULL OR user_id='';`);
    }
    // Backfill trade_type for existing rows
    if (hasColumn(db, "trades", "trade_type")) {
      exec(db, `UPDATE trades SET trade_type = COALESCE(trade_type,'BALANCE') WHERE trade_type IS NULL OR trade_type='';`);
    }

    // Backfill one_r / pnl_s for legacy schemas
    if (hasColumn(db, "trades", "one_r")) {
      if (hasColumn(db, "trades", "risk_1r")) {
        exec(db, `UPDATE trades SET one_r = COALESCE(one_r, risk_1r, 0) WHERE one_r IS NULL;`);
      } else {
        exec(db, `UPDATE trades SET one_r = COALESCE(one_r, 0) WHERE one_r IS NULL;`);
      }
    }
    if (hasColumn(db, "trades", "pnl_s")) {
      if (hasColumn(db, "trades", "pnl_dollar")) {
        exec(db, `UPDATE trades SET pnl_s = COALESCE(pnl_s, pnl_dollar, 0) WHERE pnl_s IS NULL;`);
      } else {
        exec(db, `UPDATE trades SET pnl_s = COALESCE(pnl_s, 0) WHERE pnl_s IS NULL;`);
      }
    }
  }

  // 3) integrations missing user_id (older versions)
  if (hasTable(db, "integrations")) {
    if (!hasColumn(db, "integrations", "user_id")) {
      try { exec(db, `ALTER TABLE integrations ADD COLUMN user_id TEXT;`); } catch(e) {}
    }
    if (hasColumn(db, "integrations", "user_id")) {
      exec(db, `UPDATE integrations SET user_id = COALESCE(user_id,'legacy') WHERE user_id IS NULL OR user_id='';`);
    }
  }

  // 4) trades: add new columns for multi-instrument RR + levels
  if (hasTable(db, "trades")) {
    const cols = [
      ["rr", "REAL"],
      ["sl_price", "REAL"],
      ["tp_price", "REAL"],
      ["be_price", "REAL"],
    ];
    for (const [c, t] of cols) {
      if (!hasColumn(db, "trades", c)) {
        try { exec(db, `ALTER TABLE trades ADD COLUMN ${c} ${t};`); } catch (_) {}
      }
    }
  }
}

function upgradeLegacyPasswords(db) {
  // v56: legacy password upgrade removed; keep no-op for backward compatibility
  return;
}

function ensureDemoUser(db) {
  // v51: no auto demo user
  return null;
}

async function authMiddleware(req, res, next) {
  const db = await getDb();

  // Allow unauthenticated access to auth pages and static assets
  if (req.path === "/login" || req.path === "/register" || req.path.startsWith("/public")) {
    return next();
  }

  const sid = req.cookies.sid;
  if (!sid) return res.redirect("/login");

  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [sid]);
  if (!sess) return res.redirect("/login");

  // Optional: session expiry (30 days from created_at)
  try {
    const created = new Date(sess.created_at).getTime();
    const maxAgeMs = 30 * 24 * 60 * 60 * 1000;
    if (Date.now() - created > maxAgeMs) {
      exec(db, `DELETE FROM sessions WHERE sid=?`, [sid]);
      persistDb();
      res.clearCookie("sid");
      return res.redirect("/login");
    }
  } catch (e) {}

  const user = one(db, `SELECT id,email FROM users WHERE id=?`, [sess.user_id]);
  if (!user) return res.redirect("/login");

  req.userId = user.id;
  req.userEmail = user.email;
  req.user = { id: user.id, email: user.email };
  req.sid = sid;
  req._sess = sess;

  // Attach per-user global text overrides (cached)
  req.textOverrides = loadTextOverridesForUser(db, user.id);

  // Apply overrides automatically on any HTML response from this request.
  const _origSend = res.send.bind(res);
  res.send = (body) => {
    try {
      if (typeof body === 'string' && req.textOverrides && req.textOverrides.length) {
        body = applyTextOverrides(body, req.textOverrides);
      }
    } catch (_) {}
    return _origSend(body);
  };

  return next();
}


function readSessionState(sessRow) {
  let st = {};
  let hist = [];
  try { st = sessRow?.state_json ? JSON.parse(sessRow.state_json) : {}; } catch { st = {}; }
  try { hist = sessRow?.history_json ? JSON.parse(sessRow.history_json) : []; } catch { hist = []; }
  return { st, hist };
}

function writeSessionState(db, sid, st, hist) {
  exec(db, `UPDATE sessions SET state_json=?, history_json=?, updated_at=? WHERE sid=?`,
    [JSON.stringify(st ?? {}), JSON.stringify(hist ?? []), nowIso(), sid]);
  persistDb();
}

function pushHistory(hist, st) {
  const snap = JSON.parse(JSON.stringify(st ?? {}));
  hist.push(snap);
  // cap
  if (hist.length > 30) hist = hist.slice(hist.length - 30);
  return hist;
}

function popHistory(hist) {
  if (!hist || hist.length === 0) return { hist: [], prev: null };
  const prev = hist[hist.length - 1];
  const newHist = hist.slice(0, -1);
  return { hist: newHist, prev };
}

function layout({ active="Journal", userEmail="", body="", stateLabel="", slCount=0, beCount=0 }) {
  const tabs = [
    { name:"Journal", href:"/s1" },
    { name:"Dashboard", href:"/dashboard" },
    { name:"Integrations", href:"/integrations" },
  ];
  const nav = tabs.map(t => {
    const cls = "pill" + (t.name===active ? " active" : "");
    return `<a class="${cls}" href="${t.href}">${t.name}</a>`;
  }).join("");
  return `<!doctype html>
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
      <span class="muted">DB: data.sqlite (persist)</span>
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
}

function parseNum(v) {
  if (v === "" || v === null || v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function validateBalance({ anchor, entry, val, vah, tickSize }) {
  const errors = [];
  if (!anchor) errors.push("Anchor сонгоогүй байна.");
  if (entry === null) errors.push("Entry хоосон байна.");
  if (val === null || vah === null || tickSize === null) errors.push("VAL/VAH/Tick size шаардлагатай.");
  if (errors.length) return errors;

  // rule: entry must be 2-3 ticks "inside" from anchor
  // If anchor=VAL -> entry should be VAL + [2..3]*tickSize
  // If anchor=VAH -> entry should be VAH - [2..3]*tickSize
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
  // Prefer integer ticks; round to nearest tick for practical order placement.
  const ticksRounded = Math.max(1, Math.round(ticksRaw));
  const oneRActual = ticksRounded * tv * c;
  return { ticksRaw, ticksRounded, oneRActual };
}

function computeLevels({ entry, tickSize, oneR, tickValue, contracts, rr }) {
  // User-defined: Contracts + RR, and 1R in dollars
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


// --- Minimal multipart/form-data parser (single file) ---
function parseMultipartSingleFile(req, { fileField='chart', maxBytes=8*1024*1024 } = {}) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] || '');
    const m = ct.match(/boundary=(.+)$/i);
    if (!m) return reject(new Error('No boundary'));
    const boundary = '--' + m[1];

    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('File too large'));
        try { req.destroy(); } catch (_) {}
        return;
      }
      chunks.push(chunk);
    });
    req.on('error', reject);
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      const boundaryBuf = Buffer.from(boundary);
      const parts = [];
      let start = buf.indexOf(boundaryBuf);
      while (start !== -1) {
        start += boundaryBuf.length;
        if (buf[start] === 45 && buf[start+1] === 45) break; // -- end
        // skip leading CRLF
        if (buf[start] === 13 && buf[start+1] === 10) start += 2;
        const next = buf.indexOf(boundaryBuf, start);
        if (next === -1) break;
        const part = buf.slice(start, next - 2); // remove trailing CRLF
        parts.push(part);
        start = next;
      }

      const fields = {};
      let savedFilename = null;

      for (const part of parts) {
        const sep = Buffer.from('\r\n\r\n');
        const i = part.indexOf(sep);
        if (i === -1) continue;
        const head = part.slice(0, i).toString('utf-8');
        const body = part.slice(i + sep.length);

        const cd = (head.match(/content-disposition:\s*form-data;[^\r\n]*/i) || [''])[0];
        const nameM = cd.match(/name="([^"]+)"/i);
        if (!nameM) continue;
        const name = nameM[1];
        const filenameM = cd.match(/filename="([^"]*)"/i);

        if (filenameM && name === fileField) {
          const orig = filenameM[1] || 'upload.bin';
          const ext = path.extname(orig).toLowerCase();
          const safeExt = (['.png','.jpg','.jpeg','.webp','.gif'].includes(ext)) ? ext : '.png';
          // basic image-only check using header Content-Type when provided
          const ctM = head.match(/content-type:\s*([^\r\n]+)/i);
          const partType = (ctM ? ctM[1].trim().toLowerCase() : '');
          if (partType && !partType.startsWith('image/')) {
            return reject(new Error('Images only'));
          }
          const fname = 'trade_' + Date.now() + '_' + Math.random().toString(16).slice(2) + safeExt;
          const full = path.join(UPLOAD_DIR, fname);
          try { fs.writeFileSync(full, body); } catch (e) { return reject(e); }
          savedFilename = fname;
        } else {
          fields[name] = body.toString('utf-8');
        }
      }

      resolve({ fields, filename: savedFilename });
    });
  });
}



// --- Minimal multipart/form-data parser (single file, any type) ---
function parseMultipartFileAny(req, { fileField='backup', maxBytes=25*1024*1024 } = {}) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] || '');
    const m = ct.match(/boundary=(.+)$/i);
    if (!m) return reject(new Error('No boundary'));
    const boundary = '--' + m[1];

    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('File too large'));
        try { req.destroy(); } catch (_) {}
        return;
      }
      chunks.push(chunk)
    });
    req.on('error', reject);
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      const boundaryBuf = Buffer.from(boundary);
      const parts = [];
      let start = buf.indexOf(boundaryBuf);
      while (start !== -1) {
        start += boundaryBuf.length;
        if (buf[start] === 45 && buf[start+1] === 45) break; // -- end
        if (buf[start] === 13 && buf[start+1] === 10) start += 2;
        const next = buf.indexOf(boundaryBuf, start);
        if (next === -1) break;
        const part = buf.slice(start, next - 2);
        parts.push(part);
        start = next;
      }

      const fields = {};
      let file = null;

      for (const part of parts) {
        const sep = Buffer.from('\r\n\r\n');
        const i = part.indexOf(sep);
        if (i === -1) continue;
        const head = part.slice(0, i).toString('utf-8');
        const body = part.slice(i + sep.length);

        const cd = (head.match(/content-disposition:\s*form-data;[^\r\n]*/i) || [''])[0];
        const nameM = cd.match(/name="([^"]+)"/i);
        if (!nameM) continue;
        const name = nameM[1];
        const filenameM = cd.match(/filename="([^"]*)"/i);

        if (filenameM && name === fileField) {
          file = {
            filename: filenameM[1] || 'upload.bin',
            buffer: body
          };
        } else {
          fields[name] = body.toString('utf-8');
        }
      }

      resolve({ fields, file });
    });
  });
}
// ---------- Routes ----------

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
  res.send(layout({ active:"Journal", userEmail:"", body, stateLabel:"REGISTER" }));
});

app.post("/register", async (req, res) => {
  const db = await getDb();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!email || !password || password.length < 6) {
    const body = `<div class="card"><h2>Register</h2><div class="err">Email болон password (min 6 тэмдэгт) шаардлагатай.</div><a class="pill" href="/register">Back</a></div>`;
    return res.send(layout({ active:"Journal", body, stateLabel:"REGISTER" }));
  }
  const exists = one(db, `SELECT id FROM users WHERE email=?`, [email]);
  if (exists) {
    const body = `<div class="card"><h2>Register</h2><div class="err">Энэ email бүртгэлтэй байна.</div><a class="pill" href="/register">Back</a></div>`;
    return res.send(layout({ active:"Journal", body, stateLabel:"REGISTER" }));
  }
  const hash = bcrypt.hashSync(password, 10);
  const uid = randId("u_");
  exec(db, `INSERT INTO users (id,email,password_hash,created_at) VALUES (?,?,?,?)`, [uid, email, hash, nowIso()]);
  persistDb();

  // Auto-login after register
  const sid = randId("s_");
  const ts = nowIso();
  exec(db, `INSERT INTO sessions (sid,user_id,state_json,history_json,created_at,updated_at) VALUES (?,?,?,?,?,?)`,
    [sid, uid, JSON.stringify({}), JSON.stringify([]), ts, ts]);
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
  res.send(layout({ active:"Journal", userEmail:"", body, stateLabel:"LOGIN" }));
});

app.post("/login", async (req, res) => {
  const db = await getDb();
  const email = String(req.body.email || "").trim();
  const password = String(req.body.password || "");
  const u = one(db, `SELECT * FROM users WHERE email=?`, [email]);
  if (!u || !bcrypt.compareSync(password, u.password_hash)) {
    const body = `<div class="card"><h2>Login</h2><div class="error">Алдаа: email/password буруу.</div><a class="pill" href="/login">Back</a></div>`;
    return res.send(layout({ active:"Journal", body, stateLabel:"LOGIN" }));
  }
  const sid = randId("s_");
  exec(db, `INSERT INTO sessions (sid,user_id,state_json,history_json,created_at,updated_at) VALUES (?,?,?,?,?,?)`,
    [sid, u.id, "{}", "[]", nowIso(), nowIso()]);
  persistDb();
  res.cookie("sid", sid, { httpOnly: true });
  res.redirect("/s1");
});


app.get("/logout", async (req, res) => {
  const db = await getDb();
  const sid = req.cookies.sid;
  if (sid) {
    exec(db, `DELETE FROM sessions WHERE sid=?`, [sid]);
    persistDb();
  }
  res.clearCookie("sid");
  res.redirect("/login");
});

app.post("/logout", async (req, res) => {
  const db = await getDb();
  const sid = req.cookies.sid;
  if (sid) exec(db, `DELETE FROM sessions WHERE sid=?`, [sid]);
  persistDb();
  res.clearCookie("sid");
  res.redirect("/login");
});

app.get("/", authMiddleware, (req, res) => res.redirect("/s1"));

app.get("/s1", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
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
            <option value="CUSTOM" ${st.tradeType==="CUSTOM" ? "selected" : ""}>CUSTOM (Any trade)</option>
          </select>
        </div>
      </div>
      <div style="margin-top:12px">
        <button type="submit">Next</button>
      </div>
    </form>
    <hr/>
    <form method="POST" action="/logout"><button class="secondary" type="submit">Logout</button></form>
  </div>
  `;
  res.send(layout({ active:"Journal", userEmail:req.user.email, body, stateLabel:"S1", slCount:0, beCount:0 }));
});

app.post("/s1", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const instrument = (req.body.instrument && INSTRUMENTS[String(req.body.instrument)]) ? String(req.body.instrument) : (st.instrument && INSTRUMENTS[String(st.instrument)] ? String(st.instrument) : "CL");
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const tradeType = String(req.body.tradeType || "");
  const newState = { tradeType };
  const newHist = pushHistory(hist, st);
  writeSessionState(db, req.sid, newState, newHist);
  if (tradeType === "CUSTOM") return res.redirect("/c1");
  res.redirect("/s2");
});

app.get("/c1", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  // Defaults
  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;
  const contracts = st.contracts ?? preset.contractsDefault;
  const tickSize = st.tickSize ?? preset.tickSize;
  const tickValue = st.tickValue ?? preset.tickValue;
  const direction = st.direction ?? "LONG";
  const entry = st.entry ?? "";
  const sl = st.slPrice ?? "";
  const tp = st.tpPrice ?? "";
  const errBox = st._errors && st._errors.length
    ? `<div class="error">${st._errors.map(e=>`<div>• ${escapeHtml(e)}</div>`).join("")}</div>`
    : "";

  const body = `
  <div class="card">
    <h2>Custom Trade — Any setup (no rules)</h2>
    <div class="small">BALANCE/IMBALANCE дүрэм хэрэглэхгүй. Та өөрийнхөө Entry/SL/TP/Direction-оо шууд оруулна.</div>
    <hr/>
    <form method="POST" action="/c1">
      <div class="row">
        <div class="field">
          <label>Instrument</label>
          <select name="instrument" required>
            ${Object.keys(INSTRUMENTS).map(k=>`<option value="${k}" ${instrument===k?"selected":""}>${escapeHtml(INSTRUMENTS[k].label||k)}</option>`).join("")}
          </select>
        </div>
        <div class="field">
          <label>Contracts</label>
          <input name="contracts" type="number" min="1" step="1" value="${escapeHtml(contracts)}" required/>
        </div>
      </div>

      <div class="row">
        <div class="field">
          <label>Tick size</label>
          <input name="tickSize" value="${escapeHtml(tickSize)}" readonly/>
        </div>
        <div class="field">
          <label>Tick value ($/tick, 1 contract)</label>
          <input name="tickValue" value="${escapeHtml(tickValue)}" readonly/>
        </div>
      </div>

      <div class="row">
        <div class="field">
          <label>Direction</label>
          <select name="direction" required>
            ${["LONG","SHORT"].map(d=>`<option value="${d}" ${direction===d?"selected":""}>${d}</option>`).join("")}
          </select>
        </div>
        <div class="field">
          <label>Entry price</label>
          <input name="entry" value="${escapeHtml(entry)}" required/>
        </div>
      </div>

      <div class="row">
        <div class="field">
          <label>Stop-Loss (SL)</label>
          <input name="sl" value="${escapeHtml(sl)}" required/>
        </div>
        <div class="field">
          <label>Take-Profit (TP)</label>
          <input name="tp" value="${escapeHtml(tp)}" required/>
        </div>
      </div>

      <div style="margin-top:12px">
        <button type="submit">Next (Integration)</button>
      </div>
    </form>

    <form method="POST" action="/back_c1" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>

    ${errBox}
  </div>
  `;
  res.send(layout({ active:"Journal", userEmail:req.user.email, body, stateLabel:"C1", slCount:0, beCount:0 }));
});

app.post("/back_c1", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { hist } = readSessionState(sess);
  const { hist: newHist, prev } = popHistory(hist);
  if (prev) writeSessionState(db, req.sid, prev, newHist);
  res.redirect("/s1");
});

app.post("/c1", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
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

  // Compute risk + RR from the user-provided levels.
  let oneR = null;
  let rr = null;
  let bePrice = null;
  if (errs.length === 0 && entry !== null && sl !== null && tp !== null) {
    const riskPoints = Math.abs(entry - sl);
    const profitPoints = Math.abs(tp - entry);
    rr = riskPoints > 0 ? (profitPoints / riskPoints) : null;
    if (rr !== null && Number.isFinite(rr)) rr = Math.round(rr * 100) / 100;
    const riskTicks = tickSize > 0 ? (riskPoints / tickSize) : null;
    oneR = (riskTicks !== null) ? (riskTicks * tickValue * contracts) : null;
    if (oneR !== null && Number.isFinite(oneR)) oneR = Math.round(oneR * 100) / 100;

    // BE trigger price = entry + 1R in points in trade direction
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
    writeSessionState(db, req.sid, nextState, hist);
    return res.redirect("/c1");
  }

  const newHist = pushHistory(hist, st);
  writeSessionState(db, req.sid, nextState, newHist);
  // Custom flow goes directly to Integration (Emotion) screen.
  res.redirect("/s5");
});


app.get("/s2", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const isBalance = st.tradeType === "BALANCE";
  const isImbalance = st.tradeType === "IMBALANCE";

  const val = st.val ?? "";
  const vah = st.vah ?? "";
  const tickSize = st.tickSize ?? 0.01;

  const touches = Array.isArray(st.touches) ? st.touches : ["", "", ""];
  while (touches.length < 3) touches.push("");

  const balanceAnchor = st.balanceAnchor ?? "VAL";
  const balanceEntry = st.balanceEntry ?? "";

  const direction = st.direction ?? "SHORT";
  const breakPrice = st.breakPrice ?? "";
  const pullbackPrice = st.pullbackPrice ?? "";
  const rejectionCandles = st.rejectionCandles ?? "";
  const entry3 = st.entry3 ?? "";

  const errBox = st._errors && st._errors.length
    ? `<div class="error"><b>Алдаа:</b><ul>${st._errors.map(e=>`<li>${escapeHtml(e)}</li>`).join("")}</ul></div>`
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
    <div class="small">Rules: break >= 10 tick; pullback = break side ±3 tick; rejection <=3</div>
  `;

  const body = `
  <div class="card">
    <h2>Screen 2 — Context (${escapeHtml(st.tradeType || "—")})</h2>
    <form method="POST" action="/s2">
      <div class="row">
        <div class="field"><label>VAL</label><input name="val" value="${escapeHtml(val)}" required/></div>
        <div class="field"><label>VAH</label><input name="vah" value="${escapeHtml(vah)}" required/></div>
        <div class="field"><label>Tick size</label><input name="tickSize" value="${escapeHtml(tickSize)}" required/></div>
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

      <div style="margin-top:14px" class="row">
        <button type="submit">Validate & Next</button>
      </div>
    </form>

    <form method="POST" action="/back" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>

    ${errBox}
  </div>
  `;
  res.send(layout({ active:"Journal", userEmail:req.user.email, body, stateLabel:"S2", slCount:0, beCount:0 }));
});

app.get("/s2", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const isBalance = st.tradeType === "BALANCE";
  const isImbalance = st.tradeType === "IMBALANCE";

  const val = st.val ?? "";
  const vah = st.vah ?? "";
  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;
  const tickSize = st.tickSize ?? preset.tickSize;
  const tickValue = st.tickValue ?? preset.tickValue;

  const touches = Array.isArray(st.touches) ? st.touches : ["", "", ""];
  while (touches.length < 3) touches.push("");

  const balanceAnchor = st.balanceAnchor ?? "VAL";
  const balanceEntry = st.balanceEntry ?? "";

  const direction = st.direction ?? "SHORT";
  const breakPrice = st.breakPrice ?? "";
  const pullbackPrice = st.pullbackPrice ?? "";
  const rejectionCandles = st.rejectionCandles ?? "";
  const entry3 = st.entry3 ?? "";

  const errBox = st._errors && st._errors.length
    ? `<div class="error"><b>Алдаа:</b><ul>${st._errors.map(e=>`<li>${escapeHtml(e)}</li>`).join("")}</ul></div>`
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
    <div class="small">Rules: break >= 10 tick; pullback = break side ±3 tick; rejection <=3</div>
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
          <div class="small">Instrument сонгосноор Tick size/value default орж ирнэ.</div>
        </div>
        <div class="field"><label>VAL</label><input name="val" value="${escapeHtml(val)}" required/></div>
        <div class="field"><label>VAH</label><input name="vah" value="${escapeHtml(vah)}" required/></div>
        <div class="field"><label>Tick size</label><input name="tickSize" value="${escapeHtml(tickSize)}" required/></div>
        <div class="field"><label>Tick value ($/tick, 1 contract)</label><input name="tickValue" value="${escapeHtml(tickValue)}" required/></div>
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

      <div style="margin-top:14px" class="row">
        <button type="submit">Validate & Next</button>
      </div>
    </form>

    <script>
      (function(){
        const presets = ${JSON.stringify(Object.fromEntries(Object.entries(INSTRUMENTS).map(([k,v])=>[k,{tickSize:v.tickSize,tickValue:v.tickValue}])))};
        const sel = document.querySelector('select[name="instrument"]');
        const tickSizeEl = document.querySelector('input[name="tickSize"]');
        const tickValueEl = document.querySelector('input[name="tickValue"]');
        if (!sel || !tickSizeEl || !tickValueEl) return;
        const apply = () => {
          const k = sel.value;
          if (!presets[k]) return;
          tickSizeEl.value = String(presets[k].tickSize);
          tickValueEl.value = String(presets[k].tickValue);
        };
        sel.addEventListener('change', apply);
        // Ensure correct defaults are shown even if the session was created on an older build.
        apply();
      })();
    </script>

    <form method="POST" action="/back" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>

    ${errBox}
  </div>
  `;
  res.send(layout({ active:"Journal", userEmail:req.user.email, body, stateLabel:"S2", slCount:0, beCount:0 }));
});

app.post("/back", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);
  const { hist: newHist, prev } = popHistory(hist);
  if (prev) {
    writeSessionState(db, req.sid, prev, newHist);
  }
  // decide where to go based on prev
  const target = prev && !prev.tradeType ? "/s1" : "/s1";
  res.redirect(target);
});

app.post("/s2", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  // Instrument presets (real futures tick engine)
  const instrument = (req.body.instrument && INSTRUMENTS[String(req.body.instrument)])
    ? String(req.body.instrument)
    : ((st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL");
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;

  const val = parseNum(req.body.val);
  const vah = parseNum(req.body.vah);

  // Always use real standard tick settings for the selected product.
  // (Users can still override later if you decide to add an explicit override toggle.)
  const tickSize = preset.tickSize;
  const tickValue = preset.tickValue;

  const touches = [req.body.touch1, req.body.touch2, req.body.touch3].map(parseNum);

  const nextState = { ...st, instrument, val, vah, tickSize, tickValue, touches, _errors: [] };

  if (st.tradeType === "BALANCE") {
    const balanceAnchor = String(req.body.balanceAnchor || "VAL");
    const balanceEntry = parseNum(req.body.balanceEntry);
    nextState.balanceAnchor = balanceAnchor;
    nextState.balanceEntry = balanceEntry;

    const errs = validateBalance({ anchor: balanceAnchor, entry: balanceEntry, val, vah, tickSize });
    if (errs.length) {
      nextState._errors = errs;
      writeSessionState(db, req.sid, nextState, hist);
      return res.redirect("/s2");
    }
    // direction: if anchor VAL -> LONG, anchor VAH -> SHORT
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
    if ([breakPrice,pullbackPrice,rejectionCandles,entry3,val,vah,tickSize].some(x => x===null)) errs.push("Талбарууд хоосон байна.");
    if (rejectionCandles !== null && rejectionCandles > 3) errs.push("Rejection invalid: 4+ candle бол trade no allowed.");
    // break >= 10 ticks from VAL/VAH in break direction:
    if (breakPrice !== null && tickSize !== null && val !== null && vah !== null) {
      const tenTicks = 10 * tickSize;
      // if breaking above VAH (long context) or below VAL (short context) - we accept any, but enforce distance to nearest boundary based on direction:
      if (direction === "LONG") {
        if (breakPrice < vah + tenTicks - 1e-9) errs.push("Break invalid: VAH дээрээс дор хаяж 10 tick дээш байх ёстой.");
        // pullback within ±3 ticks of VAH (break side)
        const pbDiff = Math.abs(pullbackPrice - vah);
        if (pullbackPrice !== null && pbDiff > 3 * tickSize + 1e-9) errs.push("Pullback invalid: VAH орчим ±3 tick.");
      } else if (direction === "SHORT") {
        if (breakPrice > val - tenTicks + 1e-9) errs.push("Break invalid: VAL доороос дор хаяж 10 tick доош байх ёстой.");
        const pbDiff = Math.abs(pullbackPrice - val);
        if (pullbackPrice !== null && pbDiff > 3 * tickSize + 1e-9) errs.push("Pullback invalid: VAL орчим ±3 tick.");
      }
    }
    if (errs.length) {
      nextState._errors = errs;
      writeSessionState(db, req.sid, nextState, hist);
      return res.redirect("/s2");
    }
  }

  const newHist = pushHistory(hist, st);
  writeSessionState(db, req.sid, nextState, newHist);
  res.redirect("/s3");
});

app.get("/s3", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;
  const tickSize = st.tickSize ?? preset.tickSize;
  const tickValue = st.tickValue ?? preset.tickValue;
  const contracts = st.contracts ?? preset.contractsDefault;
  const rr = st.rr ?? 2;
  const oneR = st.oneR ?? 300;
  const { ticksRaw, ticksRounded, oneRActual } = computeRiskTicks({ oneR, tickValue, contracts });
  const errBox = st._errors && st._errors.length
    ? `<div class="error"><b>Алдаа:</b><ul>${st._errors.map(e=>`<li>${escapeHtml(e)}</li>`).join("")}</ul></div>`
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
          <div class="small">Ж: 2 = +2R TP</div>
        </div>
        <div class="field" style="max-width:260px">
          <label>1R = ? $ (risk per trade)</label>
          <input name="oneR" value="${escapeHtml(String(oneR))}" required/>
        </div>
      </div>
      <div class="small" style="margin-top:8px">
        Тооцоо: 1R ticks ≈ ${escapeHtml(ticksRaw===null?"—":ticksRaw.toFixed(2))} → <b>${escapeHtml(ticksRounded===null?"—":String(ticksRounded))} ticks</b>
        (Actual 1R ≈ $${escapeHtml(oneRActual===null?"—":String(oneRActual))})
      </div>
      <div style="margin-top:12px" class="row">
        <button type="submit">Next (Levels)</button>
      </div>
    </form>

    <form method="POST" action="/back_s3" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>
  </div>
  `;
  res.send(layout({ active:"Journal", userEmail:req.user.email, body, stateLabel:"S3", slCount:0, beCount:0 }));
});

app.post("/back_s3", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { hist } = readSessionState(sess);
  const { hist: newHist, prev } = popHistory(hist);
  if (prev) writeSessionState(db, req.sid, prev, newHist);
  res.redirect("/s2");
});

app.post("/s3", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const oneR = parseNum(req.body.oneR);
  const contracts = parseNum(req.body.contracts);
  const rr = parseNum(req.body.rr);

  const errs = [];
  if (oneR === null || oneR <= 0) errs.push("1R нь 0-ээс их байх ёстой.");
  if (contracts === null || contracts <= 0) errs.push("Contracts (гэрээ) нь 0-ээс их байх ёстой.");
  if (rr === null || rr <= 0) errs.push("RR нь 0-ээс их байх ёстой.");

  const nextState = { ...st, oneR, contracts, rr, _errors: [] };
  if (errs.length) {
    nextState._errors = errs;
    writeSessionState(db, req.sid, nextState, hist);
    return res.redirect("/s3");
  }
  const newHist = pushHistory(hist, st);
  writeSessionState(db, req.sid, nextState, newHist);
  res.redirect("/s4");
});

app.get("/s4", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const entry = st.entry;
  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;
  const tickSize = st.tickSize ?? preset.tickSize;
  const tickValue = st.tickValue ?? preset.tickValue;
  const contracts = st.contracts ?? preset.contractsDefault;
  const rr = st.rr ?? 2;

  const dir = st.direction;
  const { ticksRaw, tickR, oneRPoints, tpPoints, oneRActual } = computeLevels({ entry, tickSize, oneR: st.oneR, tickValue, contracts, rr });

  function pricePlus(p, pts){ return Number((p + pts).toFixed(2)); }
  function priceMinus(p, pts){ return Number((p - pts).toFixed(2)); }

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
      <span class="kpi">1R target: $${escapeHtml(String(st.oneR))} (Actual ≈ $${escapeHtml(String(oneRActual??"—"))})</span>
      <span class="kpi">RR: ${escapeHtml(String(rr))} (TP = +RR)</span>
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

    <div class="small" style="margin-top:10px">
      <b>Order placement:</b>
      <ol>
        <li>Entry fill болсны дараа <b>initial Stop-Loss</b>-оо SL дээр байрлуул.</li>
        <li><b>Take-Profit limit</b>-ээ TP дээр байрлуул (RR-ээр тооцсон).</li>
        <li>Үнэ <b>BE trigger</b> хүрмэгц Stop-Loss-оо Entry рүү шилжүүлж <b>Break-even</b> болго.</li>
      </ol>
    </div>

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
  res.send(layout({ active:"Journal", userEmail:req.user.email, body, stateLabel:"S4", slCount:0, beCount:0 }));
});

app.post("/back_s4", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { hist } = readSessionState(sess);
  const { hist: newHist, prev } = popHistory(hist);
  if (prev) writeSessionState(db, req.sid, prev, newHist);
  res.redirect("/s3");
});

app.post("/s4_next", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const nextState = { ...st, slPrice: parseNum(req.body.sl), tpPrice: parseNum(req.body.tp), bePrice: parseNum(req.body.be) };
  const newHist = pushHistory(hist, st);
  writeSessionState(db, req.sid, nextState, newHist);
  res.redirect("/s5");
});


app.get("/s5", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const copy = getIntegrationCopy(db, req.user.id);

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

  return res.send(layout({ active:"Emotion", userEmail:req.user.email, body, stateLabel:"S5", slCount:0, beCount:0 }));
});

app.post("/s5", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const clampStep = (n) => Math.max(1, Math.min(4, Number.isFinite(n) ? n : 1));

  const nav = String(req.body.nav || "next");
  const cur = clampStep(Number(req.body.curStep || st.intStep || 1));

  // Keep emotion (only editable on step 1 UI, but accept hidden field on other steps)
  const emotion = String(req.body.emotion ?? st.emotion ?? "Тодорхойгүй").trim() || "Тодорхойгүй";

  // Collect fields by step
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
    // If release is "Үгүй", ignore location
    if (nextState.p3_release !== "Тийм") nextState.p3_releaseLocation = "";
  }

  if (cur === 4) {
    nextState.p4_change = String(req.body.p4_change ?? st.p4_change ?? "Өөрчлөлтгүй");
    nextState.p4_insight = String(req.body.p4_insight ?? st.p4_insight ?? "").trim();
    nextState.intensityAfter = String(req.body.intensityAfter ?? st.intensityAfter ?? "").trim();
  }

  // Navigation
  if (nav === "back") {
    nextState.intStep = clampStep(cur - 1);
    writeSessionState(db, req.sid, nextState, hist);
    return res.redirect("/s5");
  }

  if (nav === "next") {
    nextState.intStep = clampStep(cur + 1);
    writeSessionState(db, req.sid, nextState, hist);
    return res.redirect("/s5");
  }

  // Complete
  if (nav === "complete") {
    // Minimal requirement: insight at least 1 char (user will write 1 sentence)
    if (!String(nextState.p4_insight || "").trim()) {
      nextState._intError = "Complete хийхийн өмнө Phase 4 дээр нэг өгүүлбэрийн insight бичээрэй.";
      nextState.intStep = 4;
      writeSessionState(db, req.sid, nextState, hist);
      return res.redirect("/s5");
    }

    // Persist this Integration session to SQLite for later review
    const toInt010 = (v) => {
      const n = Number(String(v ?? "").trim());
      if (!Number.isFinite(n)) return null;
      const x = Math.max(0, Math.min(10, Math.round(n)));
      return x;
    };

    const id = randId("int_");
    const createdAt = new Date().toISOString();
    const intensityBefore = toInt010(nextState.intensityBefore);
    const intensityAfter  = toInt010(nextState.intensityAfter);

    const payload = {
      createdAt,
      emotion: nextState.emotion || "Тодорхойгүй",
      phase1: {
        bodyLocation: nextState.p1_bodyLocation || "",
        breathing: nextState.p1_breathing || "",
        intensityBefore,
        intensityNote: String(nextState.p1_intensityNote || "").trim()
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

    exec(db, `INSERT INTO integration_sessions
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

    // Mark as integrated for the rest of the flow
    nextState.integrationComplete = 1;

    const newHist = pushHistory(hist, st);
    writeSessionState(db, req.sid, nextState, newHist);
    return res.redirect("/s6");
  }

  // default
  writeSessionState(db, req.sid, nextState, hist);
  return res.redirect("/s5");
})


app.post("/integration/start", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const emotion = String(req.body.emotion || st.emotion || "FEAR");
  const mode = String(req.body.mode || st.mode || "INTEGRATED");
  const bodyScan = req.body.bodyScan ? 1 : (st.bodyScan ? 1 : 0);
  const intensityBefore = String(req.body.intensityBefore ?? st.intensityBefore ?? "");

  const nextState = {
    ...st,
    emotion,
    mode,
    bodyScan,
    intensityBefore,
    intStep: 1,
    _intError: ""
  };

  writeSessionState(db, req.sid, nextState, hist);

  return res.json({
    ok: true,
    step: 1,
    title: "Phase 1 — Grounding",
    hint: "Аюулгүй байдал + бие рүү буцах. Юу ч өөрчлөх шаардлагагүй.",
    prompt: "(1) Одоогийн энэ мөчид бие чинь аюулгүй байна уу?\n(2) Энэ мэдрэмж биеийн аль хэсэгт хамгийн тод мэдрэгдэж байна вэ?\n(3) Тэр хэсэгт юу байна? (шахалт/дулаан/хатгуулалт/хүндлэл гэх мэт) Зүгээр л анзаар.",
    value: String(nextState.intGrounding || "")
  });
});



app.post("/integration/back", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const emotion = String(req.body.emotion || st.emotion || "FEAR");
  const mode = String(req.body.mode || st.mode || "INTEGRATED");
  const bodyScan = req.body.bodyScan ? 1 : (st.bodyScan ? 1 : 0);

  const curStep = Number(req.body.curStep || st.intStep || 1);
  const stepText = String(req.body.stepText || "");
  const intensityBefore = String(req.body.intensityBefore ?? st.intensityBefore ?? "");
  const intensityAfter  = String(req.body.intensityAfter  ?? st.intensityAfter  ?? "");

  const clampStep = (n) => Math.max(1, Math.min(4, Number.isFinite(n) ? n : 1));
  const step = clampStep(curStep);

  const nextState = {
    ...st,
    emotion,
    mode,
    bodyScan,
    intensityBefore,
    intensityAfter,
    intStep: step,
    _intError: ""
  };

  // Save current text before going back (keep same rule)
  if (stepText.trim().length < 10) {
    nextState._intError = "Тухайн phase-ийн бичвэр хамгийн багадаа 10 тэмдэгт байх ёстой.";
    writeSessionState(db, req.sid, nextState, hist);
    return res.status(400).json({ ok:false, error: nextState._intError, step });
  }

  if (step === 1) nextState.intGrounding = stepText;
  if (step === 2) nextState.intAllowing = stepText;
  if (step === 3) nextState.intRelease = stepText;
  if (step === 4) nextState.intReflection = stepText;

  nextState.intStep = clampStep(step - 1);
  writeSessionState(db, req.sid, nextState, hist);

  const meta = [
    {
      title: "Phase 1 — Grounding",
      hint: "Аюулгүй байдал + бие рүү буцах. Юу ч өөрчлөх шаардлагагүй.",
      prompt: "(1) Одоогийн энэ мөчид бие чинь аюулгүй байна уу?\n(2) Энэ мэдрэмж биеийн аль хэсэгт хамгийн тод мэдрэгдэж байна вэ?\n(3) Тэр хэсэгт юу байна? (шахалт/дулаан/хатгуулалт/хүндлэл гэх мэт) Зүгээр л анзаар.",
      value: String(nextState.intGrounding || "")
    },
    {
      title: "Phase 2 — Allowing",
      hint: "Засахгүй, түлхэхгүй. Зүгээр л зөвшөөр.",
      prompt: "(1) ‘Энэ мэдрэмж яг одоо байгаагаараа байж болно.’ гэж дотроо хэлээд ажигла.\n(2) Эсэргүүцэл хаана мэдрэгдэж байна? (бие дээр)\n(3) Зөвхөн 30–60 секунд энэ мэдрэмжтэй хамт байж чадах уу?",
      value: String(nextState.intAllowing || "")
    },
    {
      title: "Phase 3 — Release",
      hint: "C философи: юу ч хийхгүй. Бие өөрөө зохицуулна.",
      prompt: "(1) Одоо ямар ч техник хэрэглэхгүй. Зүгээр л мэдрэмжтэй хамт бай.\n(2) Бие өөрөө ямар нэг өөрчлөлт хийж байна уу? (сулрал/дулаан/чимчигнэх/эсвэл нам гүм)\n(3) Чи зүгээр л ажиглаж сууж чадаж байна уу?",
      value: String(nextState.intRelease || "")
    },
    {
      title: "Phase 4 — Reflection",
      hint: "Нэг өгүүлбэрийн ухаарал. Богино, бодит.",
      prompt: "(1) Ямар өөрчлөлт мэдрэгдэв? (бага/их/өөрчлөлтгүй)\n(2) Нэг өгүүлбэрээр insight бич: юуг ойлгов?\n(3) Дараагийн алхам: өнөөдөр би юуг ‘засахгүйгээр’ зөвшөөрч чадсан бэ?",
      value: String(nextState.intReflection || "")
    }
  ];

  const newStep = nextState.intStep;
  return res.json({ ok:true, step: newStep, ...meta[newStep-1] });
});
app.post("/integration/next", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const emotion = String(req.body.emotion || st.emotion || "FEAR");
  const mode = String(req.body.mode || st.mode || "INTEGRATED");
  const bodyScan = req.body.bodyScan ? 1 : (st.bodyScan ? 1 : 0);

  const curStep = Number(req.body.curStep || st.intStep || 1);
  const stepText = String(req.body.stepText || "");
  const intensityBefore = String(req.body.intensityBefore ?? st.intensityBefore ?? "");
  const intensityAfter  = String(req.body.intensityAfter  ?? st.intensityAfter  ?? "");

  const clampStep = (n) => Math.max(1, Math.min(4, Number.isFinite(n) ? n : 1));
  const step = clampStep(curStep);

  const nextState = {
    ...st,
    emotion,
    mode,
    bodyScan,
    intensityBefore,
    intensityAfter,
    intStep: step,
    _intError: ""
  };

  if (stepText.trim().length < 10) {
    nextState._intError = "Тухайн phase-ийн бичвэр хамгийн багадаа 10 тэмдэгт байх ёстой.";
    writeSessionState(db, req.sid, nextState, hist);
    return res.status(400).json({ ok:false, error: nextState._intError, step });
  }

  if (step === 1) nextState.intGrounding = stepText;
  if (step === 2) nextState.intAllowing = stepText;
  if (step === 3) nextState.intRelease = stepText;
  if (step === 4) nextState.intReflection = stepText;

  nextState.intStep = clampStep(step + 1);
  writeSessionState(db, req.sid, nextState, hist);

  const meta = [
    {
      title: "Phase 1 — Grounding",
      hint: "Аюулгүй байдал + бие рүү буцах. Юу ч өөрчлөх шаардлагагүй.",
      prompt: "(1) Одоогийн энэ мөчид бие чинь аюулгүй байна уу?\n(2) Энэ мэдрэмж биеийн аль хэсэгт хамгийн тод мэдрэгдэж байна вэ?\n(3) Тэр хэсэгт юу байна? (шахалт/дулаан/хатгуулалт/хүндлэл гэх мэт) Зүгээр л анзаар.",
      value: String(nextState.intGrounding || "")
    },
    {
      title: "Phase 2 — Allowing",
      hint: "Засахгүй, түлхэхгүй. Зүгээр л зөвшөөр.",
      prompt: "(1) ‘Энэ мэдрэмж яг одоо байгаагаараа байж болно.’ гэж дотроо хэлээд ажигла.\n(2) Эсэргүүцэл хаана мэдрэгдэж байна? (бие дээр)\n(3) Зөвхөн 30–60 секунд энэ мэдрэмжтэй хамт байж чадах уу?",
      value: String(nextState.intAllowing || "")
    },
    {
      title: "Phase 3 — Release",
      hint: "C философи: юу ч хийхгүй. Бие өөрөө зохицуулна.",
      prompt: "(1) Одоо ямар ч техник хэрэглэхгүй. Зүгээр л мэдрэмжтэй хамт бай.\n(2) Бие өөрөө ямар нэг өөрчлөлт хийж байна уу? (сулрал/дулаан/чимчигнэх/эсвэл нам гүм)\n(3) Чи зүгээр л ажиглаж сууж чадаж байна уу?",
      value: String(nextState.intRelease || "")
    },
    {
      title: "Phase 4 — Reflection",
      hint: "Нэг өгүүлбэрийн ухаарал. Богино, бодит.",
      prompt: "(1) Ямар өөрчлөлт мэдрэгдэв? (бага/их/өөрчлөлтгүй)\n(2) Нэг өгүүлбэрээр insight бич: юуг ойлгов?\n(3) Дараагийн алхам: өнөөдөр би юуг ‘засахгүйгээр’ зөвшөөрч чадсан бэ?",
      value: String(nextState.intReflection || "")
    }
  ];

  const nextStep = nextState.intStep;
  return res.json({ ok:true, step: nextStep, ...meta[nextStep-1] });
});

app.post("/integration/complete", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const emotion = String(req.body.emotion || st.emotion || "FEAR");
  const mode = String(req.body.mode || st.mode || "INTEGRATED");
  const bodyScan = req.body.bodyScan ? 1 : (st.bodyScan ? 1 : 0);

  const intensityBefore = String(req.body.intensityBefore ?? st.intensityBefore ?? "");
  const intensityAfter  = String(req.body.intensityAfter  ?? st.intensityAfter  ?? "");

  const g = String(st.intGrounding || "").trim();
  const a = String(st.intAllowing || "").trim();
  const r = String(st.intRelease || "").trim();
  const f = String(st.intReflection || "").trim();

  if (g.length < 10 || a.length < 10 || r.length < 10 || f.length < 10) {
    const msg = "Complete хийхийн өмнө 4 фаз тус бүр дээр дор хаяж 10 тэмдэгт бичсэн байх ёстой.";
    const nextState = { ...st, _intError: msg };
    writeSessionState(db, req.sid, nextState, hist);
    return res.status(400).json({ ok:false, error: msg });
  }

  if (String(intensityAfter || "").trim() === "") {
    const msg = "Intensity AFTER (0–10)-г бөглөнө үү.";
    const nextState = { ...st, _intError: msg };
    writeSessionState(db, req.sid, nextState, hist);
    return res.status(400).json({ ok:false, error: msg });
  }

  const note = [
    `Intensity BEFORE: ${intensityBefore}`,
    `Intensity AFTER: ${intensityAfter}`,
    `\n[Grounding]\n${g}`,
    `\n[Allowing]\n${a}`,
    `\n[Release]\n${r}`,
    `\n[Reflection]\n${f}`,
  ].join('\n');

  exec(db, `INSERT INTO integrations (user_id, created_at, emotion, mode, body_scan, note)
           VALUES (?,?,?,?,?,?)`, [req.user.id, nowIso(), emotion, mode, bodyScan, note]);
  // v2 rich integration session for review
  const sessId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const payload = { ...st, note, intensityBefore, intensityAfter, emotion, mode, bodyScan };
  exec(db, `INSERT INTO integration_sessions (id, user_id, trade_id, created_at, completed_at, emotion, intensity_before, intensity_after, payload_json)
           VALUES (?,?,?,?,?,?,?,?,?)`,
           [sessId, req.user.id, null, nowIso(), nowIso(), emotion, Number(intensityBefore || 0), Number(intensityAfter || 0), JSON.stringify(payload)]);
  persistDb();

  const nextState = { ...st, note, _intError: "", intensityBefore, intensityAfter, emotion, mode, bodyScan, intStep: 4 };
  writeSessionState(db, req.sid, nextState, hist);

  return res.json({ ok:true, redirect: "/s6" });
});
;



// =========================
// Integration JSON API (for UI fetch)
// =========================
function integrationStepsC() {
  return [
    {
      key: "grounding",
      title: "Phase 1 — Grounding",
      hint: "Аюулгүй байдал + бие рүү буцах. Юу ч өөрчлөх шаардлагагүй.",
      prompt: "(1) Одоогийн энэ мөчид бие чинь аюулгүй байна уу?\n(2) Энэ мэдрэмж биеийн аль хэсэгт хамгийн тод мэдрэгдэж байна вэ?\n(3) Тэр хэсэгт юу байна? (шахалт/дулаан/хатгуулалт/хүндлэл гэх мэт) Зүгээр л анзаар."
    },
    {
      key: "allowing",
      title: "Phase 2 — Allowing",
      hint: "Засахгүй, түлхэхгүй. Зүгээр л зөвшөөр.",
      prompt: "(1) ‘Энэ мэдрэмж яг одоо байгаагаараа байж болно.’ гэж дотроо хэлээд ажигла.\n(2) Эсэргүүцэл хаана мэдрэгдэж байна? (бие дээр)\n(3) Зөвхөн 30–60 секунд энэ мэдрэмжтэй хамт байж чадах уу?"
    },
    {
      key: "release",
      title: "Phase 3 — Release",
      hint: "C философи: юу ч хийхгүй. Бие өөрөө зохицуулна.",
      prompt: "(1) Одоо ямар ч техник хэрэглэхгүй. Зүгээр л мэдрэмжтэй хамт бай.\n(2) Бие өөрөө ямар нэг өөрчлөлт хийж байна уу? (сулрал/дулаан/чимчигнэх/эсвэл нам гүм)\n(3) Чи зүгээр л ажиглаж сууж чадаж байна уу?"
    },
    {
      key: "reflection",
      title: "Phase 4 — Reflection",
      hint: "Нэг өгүүлбэрийн ухаарал. Богино, бодит.",
      prompt: "(1) Ямар өөрчлөлт мэдрэгдэв? (бага/их/өөрчлөлтгүй)\n(2) Нэг өгүүлбэрээр insight бич: юуг ойлгов?\n(3) Дараагийн алхам: өнөөдөр би юуг ‘засахгүйгээр’ зөвшөөрч чадсан бэ?"
    }
  ];
}

function integrationStatePayload(st) {
  const steps = integrationStepsC();
  const clampStep = (n) => Math.max(1, Math.min(4, Number.isFinite(n) ? n : 1));
  const cur = clampStep(Number(st.intStep ?? 1));
  const meta = steps[cur-1];
  const vals = {
    grounding: st.intGrounding ?? "",
    allowing: st.intAllowing ?? "",
    release: st.intRelease ?? "",
    reflection: st.intReflection ?? "",
  };
  return {
    step: cur,
    meta,
    value: vals[meta.key] ?? "",
    emotion: st.emotion ?? "FEAR",
    mode: st.mode ?? "INTEGRATED",
    bodyScan: !!st.bodyScan,
    intensityBefore: st.intensityBefore ?? "",
    intensityAfter: st.intensityAfter ?? "",
    error: st._intError ?? ""
  };
}

app.get("/integration/state", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);
  res.json({ ok: true, ...integrationStatePayload(st) });
});

app.post("/integration/start", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const emotion = String(req.body.emotion || st.emotion || "FEAR");
  const mode = String(req.body.mode || st.mode || "INTEGRATED");
  const bodyScan = req.body.bodyScan ? 1 : (st.bodyScan ? 1 : 0);
  const intensityBefore = String(req.body.intensityBefore ?? st.intensityBefore ?? "");

  const nextState = { ...st, emotion, mode, bodyScan, intensityBefore, intStep: 1, _intError: "" };
  writeSessionState(db, req.sid, nextState, hist);

  res.json({ ok: true, message: "Integration эхэллээ.", ...integrationStatePayload(nextState) });
});

app.post("/integration/next", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const emotion = String(req.body.emotion || st.emotion || "FEAR");
  const mode = String(req.body.mode || st.mode || "INTEGRATED");
  const bodyScan = req.body.bodyScan ? 1 : 0;

  const curStep = Number(req.body.curStep || st.intStep || 1);
  const nav = String(req.body.nav || "next");
  const stepText = String(req.body.stepText || "");
  const intensityBefore = String(req.body.intensityBefore ?? st.intensityBefore ?? "");
  const intensityAfter  = String(req.body.intensityAfter  ?? st.intensityAfter  ?? "");

  const clampStep = (n) => Math.max(1, Math.min(4, Number.isFinite(n) ? n : 1));
  const step = clampStep(curStep);

  const nextState = {
    ...st,
    emotion,
    mode,
    bodyScan,
    intensityBefore,
    intensityAfter,
    intStep: step,
    _intError: ""
  };

  // save current phase text (min 10 chars)
  if (stepText.trim().length < 10) {
    nextState._intError = "Тухайн phase-ийн бичвэр хамгийн багадаа 10 тэмдэгт байх ёстой.";
    writeSessionState(db, req.sid, nextState, hist);
    return res.status(400).json({ ok:false, error: nextState._intError, ...integrationStatePayload(nextState) });
  }

  if (step == 1) nextState.intGrounding = stepText;
  if (step == 2) nextState.intAllowing = stepText;
  if (step == 3) nextState.intRelease = stepText;
  if (step == 4) nextState.intReflection = stepText;

  if (nav === "back") nextState.intStep = clampStep(step - 1);
  if (nav === "next") nextState.intStep = clampStep(step + 1);

  writeSessionState(db, req.sid, nextState, hist);
  res.json({ ok:true, ...integrationStatePayload(nextState) });
});

app.post("/integration/complete", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st, hist } = readSessionState(sess);

  const emotion = String(req.body.emotion || st.emotion || "FEAR");
  const mode = String(req.body.mode || st.mode || "INTEGRATED");
  const bodyScan = req.body.bodyScan ? 1 : (st.bodyScan ? 1 : 0);

  const intensityBefore = String(req.body.intensityBefore ?? st.intensityBefore ?? "");
  const intensityAfter  = String(req.body.intensityAfter  ?? st.intensityAfter  ?? "");

  const g = String(st.intGrounding || "").trim();
  const a = String(st.intAllowing || "").trim();
  const r = String(st.intRelease || "").trim();
  const f = String(st.intReflection || "").trim();

  const nextState = { ...st, emotion, mode, bodyScan, intensityBefore, intensityAfter, _intError: "" };

  if (g.length < 10 || a.length < 10 || r.length < 10 || f.length < 10) {
    nextState._intError = "Complete хийхийн өмнө 4 фаз тус бүр дээр дор хаяж 10 тэмдэгт бичсэн байх ёстой.";
    nextState.intStep = 1;
    writeSessionState(db, req.sid, nextState, hist);
    return res.status(400).json({ ok:false, error: nextState._intError, ...integrationStatePayload(nextState) });
  }

  if (String(intensityAfter || "").trim() === "") {
    nextState._intError = "Intensity AFTER (0–10)-г бөглөнө үү.";
    nextState.intStep = 4;
    writeSessionState(db, req.sid, nextState, hist);
    return res.status(400).json({ ok:false, error: nextState._intError, ...integrationStatePayload(nextState) });
  }

  const note = [
    `Intensity BEFORE: ${intensityBefore}`,
    `Intensity AFTER: ${intensityAfter}`,
    `\n[Grounding]\n${g}`,
    `\n[Allowing]\n${a}`,
    `\n[Release]\n${r}`,
    `\n[Reflection]\n${f}`,
  ].join("\n");

  exec(db, `INSERT INTO integrations (user_id, created_at, emotion, mode, body_scan, note)
           VALUES (?,?,?,?,?,?)`, [req.user.id, nowIso(), emotion, mode, bodyScan, note]);
  persistDb();

  // push history
  const newHist = pushHistory(hist, st);
  const finalState = { ...nextState, note, _intError: "" };
  writeSessionState(db, req.sid, finalState, newHist);

  res.json({ ok:true, message:"Integration complete", redirect:"/s6" });
});
app.get("/s6", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const body = `
  <div class="card">
    <h2>Screen 6 — Trade result</h2>
    <form method="POST" action="/s6" enctype="multipart/form-data">
      <div class="field" style="max-width:420px">
        <label>Chart screenshot (PNG/JPG)</label>
        <input type="file" name="chart" accept="image/*" required/>
        <div class="small">Зураг хавсаргасны дараа доорх TP/BE/SL-ээс сонгоно.</div>
      </div>
      <div class="row">
        <button name="result" value="TP" type="submit">TP (+2R)</button>
        <button name="result" value="BE" type="submit">BE (0R)</button>
        <button name="result" value="SL" type="submit">SL (-1R)</button>
      </div>
    </form>

    <form method="POST" action="/back_s6" style="margin-top:10px">
      <button class="secondary" type="submit">Back</button>
    </form>
  </div>`;
  res.send(layout({ active:"Journal", userEmail:req.user.email, body, stateLabel:"S6", slCount:0, beCount:0 }));
});

app.post("/back_s6", authMiddleware, async (req, res) => {
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { hist } = readSessionState(sess);
  const { hist: newHist, prev } = popHistory(hist);
  if (prev) writeSessionState(db, req.sid, prev, newHist);
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
      return res.send(layout({ active:"Journal", userEmail:req.user.email, body, stateLabel:"S6" }));
    }
  }
  const db = await getDb();
  const sess = one(db, `SELECT * FROM sessions WHERE sid=?`, [req.sid]);
  const { st } = readSessionState(sess);

  const result = resultOverride ? resultOverride : String(req.body.result || "");
  const rr = (st.rr ?? 2);
  const { pnlR } = pnlFromResult(result, rr);
  const pnlS = (pnlR * (st.oneR ?? 0));

  const raw = JSON.stringify(st);

  const emotion = st.emotion ? String(st.emotion) : null;
  const mode = st.mode ? String(st.mode) : null;
  const bodyScan = st.bodyScan ? 1 : 0;
  const noteLen = (st.note ? String(st.note) : "").trim().length;

  const instrument = (st.instrument && INSTRUMENTS[String(st.instrument)]) ? String(st.instrument) : "CL";
  const preset = INSTRUMENTS[instrument] || INSTRUMENTS.CL;
  const contracts = st.contracts ?? preset.contractsDefault;
  const tickSize = st.tickSize ?? preset.tickSize;
  const tickValue = st.tickValue ?? preset.tickValue;
  exec(db, `INSERT INTO trades (user_id, created_at, instrument, trade_type, direction, entry, one_r, contracts, tick_size, tick_value, rr, sl_price, tp_price, be_price, result, pnl_r, pnl_s, emotion, mode, body_scan, note_len, raw_json, chart_image)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, [
    req.user.id, nowIso(), instrument, st.tradeType || null, st.direction || null, st.entry ?? null,
    st.oneR ?? null, contracts, tickSize, tickValue, rr,
    st.slPrice ?? null, st.tpPrice ?? null, st.bePrice ?? null,
    result, pnlR, pnlS,
    emotion, mode, bodyScan, noteLen,
    raw, uploadFilename
  ]);
  persistDb();

  // reset state to S1 clean
  const db2 = await getDb();
  writeSessionState(db2, req.sid, {}, []);
  res.redirect("/dashboard");
});

app.get("/dashboard", authMiddleware, async (req, res) => {
  const db = await getDb();

  const stats = one(db, `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN result='TP' THEN 1 ELSE 0 END) as tp,
      SUM(CASE WHEN result='BE' THEN 1 ELSE 0 END) as be,
      SUM(CASE WHEN result='SL' THEN 1 ELSE 0 END) as sl,
      COALESCE(SUM(pnl_r),0) as net_r,
      COALESCE(SUM(pnl_s),0) as net_s,
      COALESCE(AVG(pnl_r),0) as avg_r
    FROM trades
    WHERE user_id = ?
  `, [req.user.id]) || { total:0,tp:0,be:0,sl:0,net_r:0,net_s:0,avg_r:0 };

  const winrate = stats.total ? ((stats.tp / stats.total) * 100) : 0;

  // Mode winrate: INTEGRATED
  const integ = one(db, `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN result='TP' THEN 1 ELSE 0 END) as tp
    FROM trades
    WHERE user_id=? AND UPPER(COALESCE(mode,''))='INTEGRATED'
  `, [req.user.id]) || { total:0, tp:0 };
  const integWin = integ.total ? ((integ.tp / integ.total) * 100) : 0;

  // Instrument performance
  const byInstr = all(db, `
    SELECT instrument,
      COUNT(*) as total,
      SUM(CASE WHEN result='TP' THEN 1 ELSE 0 END) as tp,
      COALESCE(SUM(pnl_r),0) as net_r,
      COALESCE(SUM(pnl_s),0) as net_s
    FROM trades
    WHERE user_id=?
    GROUP BY instrument
    ORDER BY net_r DESC
  `, [req.user.id]);

  // Emotion impact (top 6)
  const emo = all(db, `
    SELECT COALESCE(emotion,'(none)') as emotion,
      COUNT(*) as total,
      SUM(CASE WHEN result='TP' THEN 1 ELSE 0 END) as tp,
      COALESCE(SUM(pnl_r),0) as net_r
    FROM trades
    WHERE user_id=? AND emotion IS NOT NULL
    GROUP BY emotion
    ORDER BY total DESC
    LIMIT 6
  `, [req.user.id]);

  // Recent trades
  const recent = all(db, `
    SELECT id, created_at, instrument, trade_type, direction, entry, one_r, contracts, rr,
           sl_price, tp_price, be_price, result, pnl_r, pnl_s, chart_image, mode, emotion
    FROM trades
    WHERE user_id=?
    ORDER BY id DESC
    LIMIT 20
  `, [req.user.id]);

  // Equity curve (Net R / Net $)
  const curveTrades = all(db, `
    SELECT id, created_at, pnl_r, pnl_s
    FROM trades
    WHERE user_id=?
    ORDER BY id ASC
  `, [req.user.id]);

  const buildCurve = (field) => {
    let cum = 0;
    const curve = [];
    let peak = 0;
    let maxDD = 0;
    let curDD = 0;
    for (const t of curveTrades) {
      cum += Number(t[field] || 0);
      curve.push({ id: t.id, v: cum });
      if (cum > peak) peak = cum;
      const dd = peak - cum;
      if (dd > maxDD) maxDD = dd;
      curDD = dd;
    }
    return { curve, last: cum, maxDD, curDD };
  };

  const curveR = buildCurve('pnl_r');
  const curveS = buildCurve('pnl_s');

  // Streaks
  let bestStreak = 0, worstStreak = 0;
  let curWin = 0, curLoss = 0;
  for (const t of curveTrades) {
    const r = Number(t.pnl_r || 0);
    if (r > 0) {
      curWin += 1;
      curLoss = 0;
      bestStreak = Math.max(bestStreak, curWin);
    } else if (r < 0) {
      curLoss += 1;
      curWin = 0;
      worstStreak = Math.max(worstStreak, curLoss);
    }
  }

  // Weekly summary (last 7 days, based on created_at)
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7*24*60*60*1000);
  let wNetR = 0, wTrades = 0, wTP = 0, wSL = 0;
  for (const t of curveTrades) {
    const d = new Date(String(t.created_at || ''));
    if (!isNaN(d) && d >= weekAgo) {
      wTrades += 1;
      const r = Number(t.pnl_r || 0);
      wNetR += r;
    }
  }
  const wTopEmotion = one(db, `
    SELECT COALESCE(emotion,'(none)') as emotion
    FROM trades
    WHERE user_id=? AND emotion IS NOT NULL
      AND datetime(created_at) >= datetime('now','-7 day')
    GROUP BY emotion
    ORDER BY COUNT(*) DESC
    LIMIT 1
  `, [req.user.id])?.emotion || '(none)';

  const bestInstr = byInstr.length ? byInstr[0].instrument : '-';

  const makeSpark = (curveArr, title, subtitle, unit, decimals, last, maxDD, curDD) => {
    if (!curveArr || curveArr.length < 2) {
      return `
        <div class="card-title">${escapeHtml(title)}</div>
        <div class="small muted">No trades yet</div>
      `;
    }
    const vals = curveArr.map(p => p.v);
    const minV = Math.min(...vals);
    const maxV = Math.max(...vals);
    const w = 760, h = 160, pad = 8;
    const denom = (maxV - minV) || 1;
    const pts = curveArr.map((p, i) => {
      const x = pad + (i * (w - 2*pad)) / (curveArr.length - 1);
      const y = pad + (h - 2*pad) * (1 - ((p.v - minV) / denom));
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    return `
      <div class="card-title">${escapeHtml(title)}</div>
      <div class="small muted" style="margin-bottom:8px">${escapeHtml(subtitle)}</div>
      <svg viewBox="0 0 ${w} ${h}" class="spark">
        <polyline fill="none" stroke="#111" stroke-width="2" points="${pts}" />
      </svg>
      <div class="small" style="margin-top:8px">Last: <b>${escapeHtml(Number(last).toFixed(decimals))}${escapeHtml(unit)}</b> · Max DD: <b>${escapeHtml(Number(maxDD).toFixed(decimals))}${escapeHtml(unit)}</b> · Cur DD: <b>${escapeHtml(Number(curDD).toFixed(decimals))}${escapeHtml(unit)}</b></div>
    `;
  };

  const svgR = makeSpark(curveR.curve, 'Equity Curve', 'Cumulative PnL in R over time', 'R', 2, curveR.last, curveR.maxDD, curveR.curDD);
  const svgS = makeSpark(curveS.curve, 'Equity Curve', 'Cumulative PnL in $ over time', '$', 0, curveS.last, curveS.maxDD, curveS.curDD);

  const svg = `
    <div class="eq-head">
      <div class="eq-title">
        <div class="card-title">Equity Curve</div>
        <div class="small muted">Toggle between R and $</div>
      </div>
      <div class="seg" role="tablist" aria-label="Equity Curve units">
        <button type="button" class="seg-btn" id="eqBtnR">R</button>
        <button type="button" class="seg-btn" id="eqBtnS">$</button>
      </div>
    </div>
    <div id="eqPaneR">${svgR}</div>
    <div id="eqPaneS" style="display:none">${svgS}</div>
    <script>
      (function(){
        function setMode(m){
          var rPane=document.getElementById('eqPaneR');
          var sPane=document.getElementById('eqPaneS');
          var br=document.getElementById('eqBtnR');
          var bs=document.getElementById('eqBtnS');
          if(!rPane||!sPane||!br||!bs) return;
          var mode = (m==='S') ? 'S' : 'R';
          rPane.style.display = (mode==='R') ? '' : 'none';
          sPane.style.display = (mode==='S') ? '' : 'none';
          br.classList.toggle('active', mode==='R');
          bs.classList.toggle('active', mode==='S');
          try{ localStorage.setItem('eqMode', mode); }catch(e){}
        }
        document.getElementById('eqBtnR')?.addEventListener('click', function(){ setMode('R'); });
        document.getElementById('eqBtnS')?.addEventListener('click', function(){ setMode('S'); });
        var saved = 'R';
        try{ saved = localStorage.getItem('eqMode') || 'R'; }catch(e){}
        setMode(saved);
      })();
    </script>
  `;

  const kpi = (label, value, cls='') => `
    <div class="kpi-card ${cls}">
      <div class="kpi-label">${label}</div>
      <div class="kpi-value">${value}</div>
    </div>
  `;

  const netR = Number(stats.net_r||0);
  const netS = Number(stats.net_s||0);
  const avgR = Number(stats.avg_r||0);

  const body = `
    <div class="dash">
      <div class="dash-top">
        ${kpi('Total Trades', escapeHtml(stats.total), 'blue')}
        ${kpi('Win Rate', escapeHtml(winrate.toFixed(1)) + '%', winrate >= 55 ? 'green' : (winrate <= 40 ? 'red' : 'orange'))}
        ${kpi('Net R', escapeHtml(netR.toFixed(2)) + 'R', netR >= 0 ? 'green' : 'red')}
        ${kpi('Avg R / Trade', escapeHtml(avgR.toFixed(2)) + 'R', avgR >= 0 ? 'green' : 'red')}
        ${kpi('Max Drawdown', escapeHtml(Number(curveR.maxDD||0).toFixed(2)) + 'R', (curveR.maxDD||0) <= 2 ? 'green' : ((curveR.maxDD||0) >= 6 ? 'red' : 'orange'))}
        ${kpi('Best / Worst Streak', escapeHtml(bestStreak) + 'W / ' + escapeHtml(worstStreak) + 'L', '')}
        ${kpi('Integrated Win Rate', escapeHtml(integWin.toFixed(1)) + '%', integWin >= 60 ? 'green' : (integWin && integWin <= 40 ? 'red' : 'orange'))}
        ${kpi('Net $', escapeHtml(netS.toFixed(0)) + '$', netS >= 0 ? 'green' : 'red')}
      </div>

      <div class="dash-grid">
        <div class="card">${svg}</div>

        <div class="card">
          <div class="card-title">Weekly Summary (Last 7 Days)</div>
          <div class="ws">
            <div><span class="muted">Trades</span><span class="right"><b>${escapeHtml(wTrades)}</b></span></div>
            <div><span class="muted">Net R</span><span class="right"><b>${escapeHtml(Number(wNetR).toFixed(2))}R</b></span></div>
            <div><span class="muted">Top Emotion</span><span class="right"><b>${escapeHtml(wTopEmotion)}</b></span></div>
            <div><span class="muted">Best Instrument</span><span class="right"><b>${escapeHtml(bestInstr)}</b></span></div>
          </div>
          <hr/>
          <div class="card-title">By Instrument</div>
          ${byInstr.length ? `
            <table class="tight">
              <thead><tr><th>Instr</th><th>Trades</th><th>Win%</th><th>Net R</th></tr></thead>
              <tbody>
                ${byInstr.map(r=>{
                  const wr = r.total ? (r.tp / r.total * 100) : 0;
                  return `
                    <tr>
                      <td><b>${escapeHtml(r.instrument)}</b></td>
                      <td>${escapeHtml(r.total)}</td>
                      <td>${escapeHtml(wr.toFixed(1))}%</td>
                      <td>${escapeHtml(Number(r.net_r||0).toFixed(2))}R</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          ` : `<div class="small muted">No instrument data yet</div>`}
        </div>
      </div>

      <div class="dash-grid">
        <div class="card">
          <div class="card-title">Emotion Impact (Top)</div>
          ${emo.length ? `
            <table class="tight">
              <thead><tr><th>Emotion</th><th>Trades</th><th>Win%</th><th>Net R</th></tr></thead>
              <tbody>
                ${emo.map(r=>{
                  const wr = r.total ? (r.tp / r.total * 100) : 0;
                  return `
                    <tr>
                      <td><b>${escapeHtml(r.emotion)}</b></td>
                      <td>${escapeHtml(r.total)}</td>
                      <td>${escapeHtml(wr.toFixed(1))}%</td>
                      <td>${escapeHtml(Number(r.net_r||0).toFixed(2))}R</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          ` : `<div class="small muted">No emotion data yet</div>`}
        </div>

        <div class="card">
          <div class="card-title">Data Export / Backup</div>
          <div class="small muted" style="margin-bottom:10px">Export is per-user. Backup JSON does not include image files (only references).</div>
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
            <a class="pill" href="/export/trades.csv">Download trades.csv</a>
            <a class="pill" href="/export/integrations.csv">Download integrations.csv</a>
            <a class="pill" href="/backup.json">Download backup.json</a>
          </div>
          <hr/>
          <div class="card-title" style="font-size:14px">Restore (from backup.json)</div>
          <form method="POST" action="/restore" enctype="multipart/form-data" style="margin-top:8px">
            <div class="row">
              <div class="field"><label>Backup file</label><input type="file" name="backup" accept="application/json" required></div>
            </div>
            <div class="small muted" style="margin-top:8px">Restore replaces your existing trades + integrations.</div>
            <div style="margin-top:10px"><button type="submit" onclick="return confirm('Restore will REPLACE your existing data for this account. Continue?')">Restore now</button></div>
          </form>
        </div>


        <div class="card">
          <div class="card-title">Recent Trades</div>
          <table class="tight">
            <thead><tr>
              <th>#</th><th>Time</th><th>Instr</th><th>Dir</th><th>Contracts</th><th>RR</th><th>R</th><th>$</th><th>Mode</th><th>Emotion</th><th>Chart</th>
            </tr></thead>
            <tbody>
              ${recent.map(r=>`
                <tr>
                  <td>${escapeHtml(r.id)}</td>
                  <td>${escapeHtml(r.created_at)}</td>
                  <td><b>${escapeHtml(r.instrument)}</b></td>
                  <td>${escapeHtml(r.direction)}</td>
                  <td>${escapeHtml(r.contracts)}</td>
                  <td>${escapeHtml(r.rr)}</td>
                  <td>${escapeHtml(Number(r.pnl_r||0).toFixed(2))}</td>
                  <td>${escapeHtml(Number(r.pnl_s||0).toFixed(0))}</td>
                  <td>${escapeHtml(r.mode || '')}</td>
                  <td>${escapeHtml(r.emotion || '')}</td>
                  <td>${r.chart_image ? `<a href="/uploads/${escapeHtml(r.chart_image)}" target="_blank">View</a>` : '—'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  res.send(layout({ active:"Dashboard", userEmail:req.user.email, body, stateLabel:"DASH", slCount:0, beCount:0 }));
});

// ---- Admin: Integration Text Editor (editable copy + live preview) ----

function editorField(label, key, value, rows=3) {
  return `
    <div class="field" style="margin-top:10px">
      <label>${escapeHtml(label)} <span class="muted" style="font-weight:500">(${escapeHtml(key)})</span></label>
      <textarea class="copy-field" name="${escapeHtml(key)}" data-key="${escapeHtml(key)}" rows="${rows}" placeholder="...">${escapeHtml(value || "")}</textarea>
    </div>
  `;
}

function renderIntegrationTextEditorPage(copy) {
  const fields = [];
  fields.push(editorField("Safety note", "safety_note", copy.safety_note, 3));
  fields.push(editorField("Жижиг дүрэм — гарчиг", "small_rules_title", copy.small_rules_title, 1));
  fields.push(editorField("Жижиг дүрэм — тайлбар", "small_rules_body", copy.small_rules_body, 2));
  fields.push(editorField("Timer hint (доорх тайлбар)", "timer_hint", copy.timer_hint, 2));

  fields.push(editorField("Phase 1 — дээд тайлбар", "p1_sub", copy.p1_sub, 2));
  fields.push(editorField("Phase 1 — чиглүүлэг гарчиг", "p1_guide_title", copy.p1_guide_title, 1));
  fields.push(editorField("Phase 1 — чиглүүлэг текст", "p1_guide_body", copy.p1_guide_body, 2));
  fields.push(editorField("Phase 1 — mantra", "p1_mantra", copy.p1_mantra, 1));
  fields.push(editorField("Phase 1 — list 1", "p1_li1", copy.p1_li1, 2));
  fields.push(editorField("Phase 1 — list 2", "p1_li2", copy.p1_li2, 2));

  fields.push(editorField("Phase 2 — дээд тайлбар", "p2_sub", copy.p2_sub, 2));
  fields.push(editorField("Phase 2 — чиглүүлэг гарчиг", "p2_guide_title", copy.p2_guide_title, 1));
  fields.push(editorField("Phase 2 — чиглүүлэг текст", "p2_guide_body", copy.p2_guide_body, 2));
  fields.push(editorField("Phase 2 — list 1", "p2_li1", copy.p2_li1, 2));
  fields.push(editorField("Phase 2 — list 2", "p2_li2", copy.p2_li2, 2));

  fields.push(editorField("Phase 3 — дээд тайлбар", "p3_sub", copy.p3_sub, 2));
  fields.push(editorField("Phase 3 — чиглүүлэг гарчиг", "p3_guide_title", copy.p3_guide_title, 1));
  fields.push(editorField("Phase 3 — чиглүүлэг текст", "p3_guide_body", copy.p3_guide_body, 2));
  fields.push(editorField("Phase 3 — list 1", "p3_li1", copy.p3_li1, 2));
  fields.push(editorField("Phase 3 — list 2", "p3_li2", copy.p3_li2, 2));

  fields.push(editorField("Phase 4 — дээд тайлбар", "p4_sub", copy.p4_sub, 2));
  fields.push(editorField("Phase 4 — acceptance гарчиг", "p4_accept_title", copy.p4_accept_title, 1));
  fields.push(editorField("Phase 4 — acceptance текст ({emotion} placeholder)", "p4_accept_body", copy.p4_accept_body, 2));
  fields.push(editorField("Phase 4 — reflection гарчиг", "p4_reflect_title", copy.p4_reflect_title, 1));
  fields.push(editorField("Phase 4 — reflection 1", "p4_reflect_li1", copy.p4_reflect_li1, 2));
  fields.push(editorField("Phase 4 — reflection 2", "p4_reflect_li2", copy.p4_reflect_li2, 2));
  fields.push(editorField("Phase 4 — reflection 3", "p4_reflect_li3", copy.p4_reflect_li3, 2));
  // --- Labels & Options (all selectable texts) ---
  fields.push(editorField("LABEL — Одоогийн мэдрэмж", "lbl_emotion", copy.lbl_emotion, 1));
  fields.push(editorField("OPTIONS — Мэдрэмжүүд (line per option)", "opt_emotions", copy.opt_emotions, 3));

  fields.push(editorField("LABEL — Phase1: Биеийн аль хэсэгт…", "lbl_p1_bodyLocation", copy.lbl_p1_bodyLocation, 2));
  fields.push(editorField("OPTIONS — Body locations (line per option)", "opt_bodyLocations", copy.opt_bodyLocations, 4));
  fields.push(editorField("LABEL — Phase1: Амьсгал чинь…", "lbl_p1_breathing", copy.lbl_p1_breathing, 2));
  fields.push(editorField("OPTIONS — Breathing (line per option)", "opt_breathing", copy.opt_breathing, 3));

  fields.push(editorField("LABEL — Intensity (Before)", "lbl_intensity_before", copy.lbl_intensity_before, 2));
  fields.push(editorField("LABEL — Intensity (After)", "lbl_intensity_after", copy.lbl_intensity_after, 2));
  fields.push(editorField("LABEL — Optional tag", "lbl_intensity_optional", copy.lbl_intensity_optional, 1));
  fields.push(editorField("LABEL — Intensity note", "lbl_intensity_note", copy.lbl_intensity_note, 2));
  fields.push(editorField("PLACEHOLDER — Intensity note", "ph_intensity_note", copy.ph_intensity_note, 2));

  fields.push(editorField("LABEL — Phase2: Fixing question", "lbl_p2_fixing", copy.lbl_p2_fixing, 2));
  fields.push(editorField("LABEL — Phase2: Observing/shape question", "lbl_p2_observing", copy.lbl_p2_observing, 2));
  fields.push(editorField("OPTIONS — Yes/No (line per option)", "opt_yesno", copy.opt_yesno, 2));
  fields.push(editorField("OPTIONS — Shapes (line per option)", "opt_p2_shapes", copy.opt_p2_shapes, 4));

  fields.push(editorField("LABEL — Phase3: Release question", "lbl_p3_release", copy.lbl_p3_release, 2));
  fields.push(editorField("LABEL — Phase3: Release location", "lbl_p3_releaseLocation", copy.lbl_p3_releaseLocation, 2));
  fields.push(editorField("OPTIONS — Release locations (line per option)", "opt_releaseLocations", copy.opt_releaseLocations, 3));
  fields.push(editorField("LABEL — Phase3: Staying question", "lbl_p3_staying", copy.lbl_p3_staying, 2));
  fields.push(editorField("OPTIONS — Easy/Hard (line per option)", "opt_easyhard", copy.opt_easyhard, 2));
  fields.push(editorField("HINT — Release location disabled", "hint_releaseLocation_disabled", copy.hint_releaseLocation_disabled, 1));

  fields.push(editorField("LABEL — Phase4: Change question", "lbl_p4_change", copy.lbl_p4_change, 2));
  fields.push(editorField("OPTIONS — Change (line per option)", "opt_change", copy.opt_change, 2));
  fields.push(editorField("LABEL — Phase4: Insight label", "lbl_p4_insight", copy.lbl_p4_insight, 2));
  fields.push(editorField("PLACEHOLDER — Phase4 insight", "ph_p4_insight", copy.ph_p4_insight, 1));

  fields.push(editorField("BUTTON — Back", "btn_back", copy.btn_back, 1));
  fields.push(editorField("BUTTON — Next", "btn_next", copy.btn_next, 1));
  fields.push(editorField("BUTTON — Complete", "btn_complete", copy.btn_complete, 1));
  fields.push(editorField("BUTTON — Back (Journal)", "btn_back_journal", copy.btn_back_journal, 1));


  return `
    <div class="card">
      <h2>Integration Text Editor</h2>
      <div class="small muted" style="margin-top:6px">
        Эндээс Screen 5 дээр гарч байгаа бүх чиглүүлэг текстээ засна. Зүүн талд edit, баруун талд live preview.
        <br/>Хадгалахгүйгээр preview дээр шууд тусна. “Save” дарахад SQLite-д хадгална.
      </div>

      <div class="row" style="gap:14px; align-items:flex-start; margin-top:12px">
        <div style="flex:1; min-width:360px">
          <form method="POST" action="/admin/integration-text" id="copyForm">
            ${fields.join("\n")}

            <div class="row" style="margin-top:12px; gap:10px">
              <button type="submit" id="saveBtn">Save</button>
              <button class="secondary" type="submit" formaction="/admin/integration-text/reset" formmethod="POST">Reset to default</button>
            </div>
          </form>
        </div>

        <div style="flex:1; min-width:360px">
          <div class="small muted" style="margin-bottom:8px">Preview</div>
          <iframe id="previewFrame" src="/admin/integration-text/preview" style="width:100%; height:900px; border:1px solid rgba(255,255,255,0.12); border-radius:14px;"></iframe>
        </div>
      </div>

      <script>
        (function(){
          const frame = document.getElementById('previewFrame');
          const fields = Array.from(document.querySelectorAll('.copy-field'));

          function sendAll(){
            const payload = {};
            for (const el of fields) payload[el.dataset.key] = el.value;
            frame.contentWindow && frame.contentWindow.postMessage({type:'copy_update_all', payload}, '*');
          }

          // When iframe is ready
          window.addEventListener('message', (e)=>{
            if (!e || !e.data) return;
            if (e.data.type === 'copy_preview_ready') sendAll();
          });

          // Live update (debounced)
          let t = null;
          function schedule(){
            if (t) clearTimeout(t);
            t = setTimeout(sendAll, 120);
          }

          fields.forEach(el=>{
            el.addEventListener('input', schedule);
          });

          // Initial push
          setTimeout(sendAll, 300);
        })();
      </script>
    </div>
  `;
}

app.get('/admin/integration-text', authMiddleware, async (req, res) => {
  const db = await getDb();
  const copy = getIntegrationCopy(db, req.user.id);
  const body = renderIntegrationTextEditorPage(copy);
  return res.send(layout({ active:"Settings", userEmail:req.user.email, body, stateLabel:"ADMIN", slCount:0, beCount:0 }));
});

app.post('/admin/integration-text', authMiddleware, async (req, res) => {
  const db = await getDb();
  const nextCopy = { ...DEFAULT_COPY };
  for (const k of Object.keys(DEFAULT_COPY)) {
    if (req.body[k] !== undefined) nextCopy[k] = String(req.body[k]);
  }
  saveIntegrationCopy(db, req.user.id, nextCopy);
  return res.redirect('/admin/integration-text');
});

app.post('/admin/integration-text/reset', authMiddleware, async (req, res) => {
  const db = await getDb();
  resetIntegrationCopy(db, req.user.id);
  return res.redirect('/admin/integration-text');
});

app.get('/admin/integration-text/preview', authMiddleware, async (req, res) => {
  const db = await getDb();
  const copy = getIntegrationCopy(db, req.user.id);
  const st = {
    emotion: "Айдас",
    p1_bodyLocation: "Цээж",
    p1_breathing: "Жигд",
    intensityBefore: "7",
    p2_fixing: "Үгүй",
    p2_observing: "Даралттай",
    p3_release: "Үгүй",
    p3_releaseLocation: "Цээж",
    p3_staying: "Хэцүү",
    p4_change: "Бага",
    intensityAfter: "3",
    p4_insight: "Би яарахгүй байж чадна."
  };
  const body = renderScreen5({ st, cur: 1, errHtml: "", copy });

  // Minimal wrapper + postMessage bridge
  const html = `<!doctype html>
  <html><head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <link rel="stylesheet" href="/public/styles.css"/>
  </head><body style="margin:0; padding:12px; background: var(--bg, #0b1020)">
    ${body}
    <script>
      (function(){
        function applyAll(payload){
          if (!payload) return;
          for (const [k,v] of Object.entries(payload)) {
            const el = document.querySelector('[data-copy="'+k+'"]');
            if (el) {
              // For acceptance template, we store raw template with {emotion}; keep emotion from data-emotion.
              if (k === 'p4_accept_body') {
                const emo = el.getAttribute('data-emotion') || 'Тодорхойгүй';
                const txt = String(v || '').replaceAll('{emotion}', emo);
                el.textContent = txt;
              } else {
                el.textContent = String(v ?? '');
              }
            }
          }
        }
        window.addEventListener('message', (e)=>{
          if (!e || !e.data) return;
          if (e.data.type === 'copy_update_all') applyAll(e.data.payload);
        });
        // Tell parent we are ready
        try { parent.postMessage({type:'copy_preview_ready'}, '*'); } catch (_) {}
      })();
    </script>
  </body></html>`;
  return res.send(html);
});



// ---- Export / Backup / Restore ----

// ---- Admin: Global UI Text Overrides (all screens) ----
app.get('/admin/texts', authMiddleware, async (req, res) => {
  const db = await getDb();
  const rows = all(db, `SELECT from_text, to_text, updated_at FROM text_overrides WHERE user_id=? ORDER BY updated_at DESC`, [req.userId]) || [];

  const items = rows.map((r, i) => {
    return `
      <div class="callout" style="margin-top:10px">
        <div class="row" style="gap:12px; align-items:flex-start">
          <div class="field" style="flex:1">
            <label>Original text (exact match)</label>
            <textarea name="from_text[]" rows="2" readonly>${esc(r.from_text)}</textarea>
          </div>
          <div class="field" style="flex:1">
            <label>Replace with</label>
            <textarea name="to_text[]" rows="2">${esc(r.to_text)}</textarea>
          </div>
          <div class="field" style="min-width:140px">
            <label>Delete</label>
            <div class="small muted">Remove this override</div>
            <input type="checkbox" name="del[]" value="${i}" />
            <input type="hidden" name="idx[]" value="${i}" />
          </div>
        </div>
        <div class="small muted" style="margin-top:6px">Updated: ${esc(r.updated_at)}</div>
      </div>
    `;
  }).join("\n");

  const body = `
  <div class="card">
    <h2>Admin — Global Text Overrides</h2>
    <div class="small muted" style="margin-top:6px">
      Энд хийсэн өөрчлөлт <b>апп-ын бүх хэсэгт</b> (Journal, Dashboard, Integrations, Screen1–5 г.м.) хэрэгжинэ.
      Текст солихдоо UI дээр харагдаж байгаа өгүүлбэрийг <b>яг тэр чигээр нь</b> (space, punctuation хүртэл) “Original text” талбарт оруул.
    </div>

    <div class="callout" style="margin-top:12px">
      <div style="font-weight:700; margin-bottom:6px">Add new override</div>
      <form method="POST" action="/admin/texts/add">
        <div class="row" style="gap:12px; align-items:flex-start">
          <div class="field" style="flex:1">
            <label>Original text (exact match)</label>
            <textarea name="from_text" rows="2" placeholder="Ж: Screen 1 — Trade type" required></textarea>
          </div>
          <div class="field" style="flex:1">
            <label>Replace with</label>
            <textarea name="to_text" rows="2" placeholder="Ж: Screen 1 — Арилжааны төрөл" required></textarea>
          </div>
        </div>
        <div class="row" style="margin-top:10px; gap:10px">
          <button type="submit">Add</button>
          <a class="pill" href="/s1">Open Journal</a>
          <a class="pill" href="/dashboard">Open Dashboard</a>
          <a class="pill" href="/integrations">Open Integrations</a>
        </div>
      </form>
    </div>

    <form method="POST" action="/admin/texts/save" style="margin-top:14px">
      <h3 style="margin:0">Existing overrides</h3>
      ${items || `<div class="small muted" style="margin-top:8px">Одоогоор override алга байна.</div>`}

      <div class="row" style="margin-top:14px; gap:10px">
        <button type="submit">Save changes</button>
        <button class="secondary" type="submit" formaction="/admin/texts/clear" formmethod="POST">Clear all</button>
      </div>
    </form>
  </div>
  `;
  res.send(layout({ active: "Journal", userEmail: req.userEmail, body, stateLabel: "—", slCount: 0, beCount: 0 }));
});

app.post('/admin/texts/add', authMiddleware, async (req, res) => {
  const db = await getDb();
  const fromText = String(req.body.from_text || "").trim();
  const toText = String(req.body.to_text || "").trim();
  if (!fromText || !toText) return res.redirect('/admin/texts');

  const now = new Date().toISOString();
  exec(db, `INSERT INTO text_overrides(user_id, from_text, to_text, updated_at)
            VALUES (?,?,?,?)
            ON CONFLICT(user_id, from_text) DO UPDATE SET to_text=excluded.to_text, updated_at=excluded.updated_at;`,
            [req.userId, fromText, toText, now]);
  TEXT_OVERRIDE_CACHE.delete(req.userId);
  return res.redirect('/admin/texts');
});

app.post('/admin/texts/save', authMiddleware, async (req, res) => {
  const db = await getDb();
  const fromArr = [].concat(req.body["from_text[]"] || []);
  const toArr = [].concat(req.body["to_text[]"] || []);
  const delIdx = new Set([].concat(req.body["del[]"] || req.body.del || []).map(x => String(x)));

  const now = new Date().toISOString();
  // Update or delete existing overrides
  for (let i = 0; i < fromArr.length; i++) {
    const fromText = String(fromArr[i] || "");
    if (!fromText) continue;
    if (delIdx.has(String(i))) {
      exec(db, `DELETE FROM text_overrides WHERE user_id=? AND from_text=?`, [req.userId, fromText]);
    } else {
      const toText = String(toArr[i] ?? "");
      exec(db, `INSERT INTO text_overrides(user_id, from_text, to_text, updated_at)
                VALUES (?,?,?,?)
                ON CONFLICT(user_id, from_text) DO UPDATE SET to_text=excluded.to_text, updated_at=excluded.updated_at;`,
                [req.userId, fromText, toText, now]);
    }
  }
  TEXT_OVERRIDE_CACHE.delete(req.userId);
  return res.redirect('/admin/texts');
});

app.post('/admin/texts/clear', authMiddleware, async (req, res) => {
  const db = await getDb();
  exec(db, `DELETE FROM text_overrides WHERE user_id=?`, [req.userId]);
  TEXT_OVERRIDE_CACHE.delete(req.userId);
  return res.redirect('/admin/texts');
});


app.get("/export/trades.csv", authMiddleware, async (req, res) => {
  const db = await getDb();
  const rows = all(db, `
    SELECT id, created_at, instrument, trade_type, direction, entry, one_r, contracts, tick_size, tick_value, rr,
           sl_price, tp_price, be_price, result, pnl_r, pnl_s, emotion, mode, body_scan, note_len, chart_image
    FROM trades
    WHERE user_id=?
    ORDER BY id ASC
  `, [req.user.id]);

  const headers = [
    'id','created_at','instrument','trade_type','direction','entry','one_r','contracts','tick_size','tick_value','rr',
    'sl_price','tp_price','be_price','result','pnl_r','pnl_s','emotion','mode','body_scan','note_len','chart_image'
  ];

  const csv = rowsToCsv(headers, rows);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="trades.csv"');
  res.send(csv);
});

app.get("/export/integrations.csv", authMiddleware, async (req, res) => {
  const db = await getDb();
  const rows = all(db, `
    SELECT id, created_at, emotion, mode, body_scan, note
    FROM integrations
    WHERE user_id=?
    ORDER BY id ASC
  `, [req.user.id]);

  const headers = ['id','created_at','emotion','mode','body_scan','note'];
  const csv = rowsToCsv(headers, rows);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="integrations.csv"');
  res.send(csv);
});

app.get("/backup.json", authMiddleware, async (req, res) => {
  const db = await getDb();
  const trades = all(db, `
    SELECT created_at, instrument, trade_type, direction, entry, one_r, contracts, tick_size, tick_value, rr,
           sl_price, tp_price, be_price, result, pnl_r, pnl_s, emotion, mode, body_scan, note_len, raw_json, chart_image
    FROM trades
    WHERE user_id=?
    ORDER BY id ASC
  `, [req.user.id]);

  const integrations = all(db, `
    SELECT created_at, emotion, mode, body_scan, note
    FROM integrations
    WHERE user_id=?
    ORDER BY id ASC
  `, [req.user.id]);

  const payload = {
    version: 1,
    exported_at: nowIso(),
    user: { email: req.user.email },
    trades,
    integrations
  };

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="backup.json"');
  res.send(JSON.stringify(payload, null, 2));
});

app.post("/restore", authMiddleware, async (req, res) => {
  const db = await getDb();
  try {
    const isMultipart = String(req.headers['content-type'] || '').includes('multipart/form-data');
    if (!isMultipart) {
      return res.status(400).send('Restore requires multipart/form-data');
    }
    const { file } = await parseMultipartFileAny(req, { fileField: 'backup', maxBytes: 25*1024*1024 });
    if (!file || !file.buffer) {
      return res.status(400).send('No file');
    }
    const txt = file.buffer.toString('utf-8');
    const data = JSON.parse(txt);
    const trades = Array.isArray(data?.trades) ? data.trades : [];
    const integrations = Array.isArray(data?.integrations) ? data.integrations : [];

    // Replace current user's data
    exec(db, `DELETE FROM trades WHERE user_id=?`, [req.user.id]);
    exec(db, `DELETE FROM integrations WHERE user_id=?`, [req.user.id]);

    for (const t of trades) {
      exec(db, `INSERT INTO trades (user_id, created_at, instrument, trade_type, direction, entry, one_r, contracts, tick_size, tick_value, rr, sl_price, tp_price, be_price, result, pnl_r, pnl_s, emotion, mode, body_scan, note_len, raw_json, chart_image)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, [
        req.user.id,
        String(t.created_at || nowIso()),
        String(t.instrument || 'CL'),
        t.trade_type != null ? String(t.trade_type) : null,
        t.direction != null ? String(t.direction) : null,
        t.entry != null ? Number(t.entry) : null,
        t.one_r != null ? Number(t.one_r) : null,
        t.contracts != null ? Number(t.contracts) : 1,
        t.tick_size != null ? Number(t.tick_size) : (INSTRUMENTS[String(t.instrument||'CL')]?.tickSize || 0.01),
        t.tick_value != null ? Number(t.tick_value) : (INSTRUMENTS[String(t.instrument||'CL')]?.tickValue || 10),
        t.rr != null ? Number(t.rr) : 2,
        t.sl_price != null ? Number(t.sl_price) : null,
        t.tp_price != null ? Number(t.tp_price) : null,
        t.be_price != null ? Number(t.be_price) : null,
        String(t.result || 'BE'),
        t.pnl_r != null ? Number(t.pnl_r) : 0,
        t.pnl_s != null ? Number(t.pnl_s) : 0,
        t.emotion != null ? String(t.emotion) : null,
        t.mode != null ? String(t.mode) : null,
        t.body_scan ? 1 : 0,
        t.note_len != null ? Number(t.note_len) : null,
        t.raw_json != null ? String(t.raw_json) : null,
        null
      ]);
    }

    for (const it of integrations) {
      exec(db, `INSERT INTO integrations (user_id, created_at, emotion, mode, body_scan, note)
               VALUES (?,?,?,?,?,?)`, [
        req.user.id,
        String(it.created_at || nowIso()),
        String(it.emotion || ''),
        String(it.mode || ''),
        it.body_scan ? 1 : 0,
        String(it.note || '')
      ]);
    }

    persistDb();
    return res.redirect('/dashboard');
  } catch (e) {
    return res.status(400).send('Restore failed: ' + escapeHtml(e.message || String(e)));
  }
});

app.get("/emotion-dashboard", authMiddleware, async (req, res) => res.redirect("/s5"));

// start
getDb().then(() => {
  
// =========================
// Integration Review (SQLite - v2)
// =========================
app.get("/integrations", authMiddleware, async (req, res) => {
  const db = await getDb();
  const rows = all(db, `SELECT id, created_at, emotion, intensity_before, intensity_after
                        FROM integration_sessions
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                        LIMIT 200`, [req.user.id]);

  const body = `
    <h2>Integration Review</h2>
    <div class="muted" style="margin:6px 0 14px 0">Бүх Integration session хадгалагдана. Дэлгэрэнгүйг нээж хараарай.</div>
    <div class="card" style="padding:14px">
      <table class="table" style="width:100%">
        <thead>
          <tr>
            <th>Date</th>
            <th>Emotion</th>
            <th>Before</th>
            <th>After</th>
            <th>Δ</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(r => {
            const b = (r.intensity_before ?? "");
            const a = (r.intensity_after ?? "");
            const d = (Number(b)||0) - (Number(a)||0);
            return `<tr>
              <td>${escapeHtml(r.created_at)}</td>
              <td>${escapeHtml(r.emotion || "")}</td>
              <td>${escapeHtml(String(b))}</td>
              <td>${escapeHtml(String(a))}</td>
              <td>${escapeHtml(String(d))}</td>
              <td><a class="btn" style="padding:6px 10px" href="/integrations/${encodeURIComponent(r.id)}">View</a></td>
            </tr>`;
          }).join("")}
        </tbody>
      </table>
    </div>
    <div style="margin-top:12px">
      <a class="btn" href="/export/integrations.csv">Export (legacy CSV)</a>
    </div>
  `;
  return res.send(layout({ active:"Integrations", userEmail: req.user.email, body }));
});

app.get("/integrations/:id", authMiddleware, async (req, res) => {
  const db = await getDb();
  const row = one(db, `SELECT * FROM integration_sessions WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id]);
  if (!row) return res.status(404).send(layout({ active:"Integrations", userEmail:req.user.email, body:`<h2>Not found</h2>` }));

  let payload = {};
  try { payload = JSON.parse(row.payload_json || "{}"); } catch (_) { payload = {}; }

  const pretty = escapeHtml(JSON.stringify(payload, null, 2));
  const delta = (Number(row.intensity_before)||0) - (Number(row.intensity_after)||0);

  const body = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px">
      <h2 style="margin:0">Integration Detail</h2>
      <a class="btn" href="/integrations">Back</a>
    </div>
    <div class="card" style="padding:14px;margin-top:12px">
      <div class="row" style="gap:18px;flex-wrap:wrap">
        <div><div class="muted">Date</div><div>${escapeHtml(row.created_at)}</div></div>
        <div><div class="muted">Emotion</div><div>${escapeHtml(row.emotion||"")}</div></div>
        <div><div class="muted">Before</div><div>${escapeHtml(String(row.intensity_before??""))}</div></div>
        <div><div class="muted">After</div><div>${escapeHtml(String(row.intensity_after??""))}</div></div>
        <div><div class="muted">Δ</div><div>${escapeHtml(String(delta))}</div></div>
      </div>
    </div>

    <div class="card" style="padding:14px;margin-top:12px">
      <div class="muted" style="margin-bottom:8px">Payload (raw JSON)</div>
      <pre style="white-space:pre-wrap;line-height:1.35;background:#0B1626;padding:12px;border-radius:12px;border:1px solid rgba(79,195,247,0.25);overflow:auto">${pretty}</pre>
    </div>
  `;
  return res.send(layout({ active:"Integrations", userEmail: req.user.email, body }));
});

app.listen(PORT, () => console.log(`${APP_TITLE} running on http://localhost:${PORT}`));
}).catch(err => {
  console.error("DB init error:", err);
  process.exit(1);
});


// Redirect legacy emotion routes to Integration (Screen 5)
app.get("/emotion", authMiddleware, async (req, res) => res.redirect("/s5"));}
