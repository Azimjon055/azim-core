// Azim Core — backend server
// Serves the app (index.html) and stores all data as one JSON blob on disk,
// so every computer that opens this server's URL shares the same data.
//
// Password security:
// - Passwords are never stored or transmitted in plain text after the first read.
// - Hashing uses bcrypt (bcryptjs, pure JS — no native build step needed).
// - Login is verified entirely on the server; the client never receives a
//   password or password hash for any user, including its own.
// - Any legacy plain-text password found on disk is hashed automatically
//   the first time it's touched (login or state read) and the plain value
//   is deleted — no manual migration step required.

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// --- proprietary software — license check --------------------------------
// © Абдуҳакимов Азимҷон Олимович. Ҳама ҳуқуқҳо ҳифз шудаанд.
// © Abdukhakimov Azimjon Olimovich. All rights reserved.
//
// This is proprietary software, not open source. Copying this code to run
// your own instance without authorization is a license/copyright
// violation. Only the SHA-256 hash of the license key lives in this file —
// the key itself is never stored in the repo, so having the source code
// alone is not enough to run a working copy. The server refuses to start
// unless the LICENSE_KEY environment variable matches this hash.
const LICENSE_KEY_HASH = 'f09f387dc27bf6801750be1f915d3c3d51380ac6bfd0cc752c66b67ae52c291e';
function isLicensed() {
  const key = process.env.LICENSE_KEY || '';
  if (!key) return false;
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return hash === LICENSE_KEY_HASH;
}
if (!isLicensed()) {
  console.error('');
  console.error('════════════════════════════════════════════════════════════');
  console.error(' LICENSE ERROR — Azim Core');
  console.error(' This server will not start: the LICENSE_KEY environment');
  console.error(' variable is missing or incorrect.');
  console.error(' This is proprietary software (© Абдуҳакимов Азимҷон Олимович).');
  console.error(' Set LICENSE_KEY in your hosting provider Variables/');
  console.error(' Environment settings to the key issued by the author.');
  console.error('════════════════════════════════════════════════════════════');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'state.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Default accounts, matching the ones the app has always shipped with.
// Hashed and written straight to disk so the login screen always has at
// least these accounts to offer — the server no longer depends on a
// browser visiting first to bootstrap the user list.
const DEFAULT_USERS_SEED = {
  admin: { name: 'Администратор', role: 'admin', password: 'admin123' },
  mahzan: { name: 'Мудири махзан', role: 'mudir', password: 'mahzan123' },
  kassa1: { name: 'Кассир №1', role: 'kassir', cashbox: 'kassa1', password: 'kassa123' },
  kassa2: { name: 'Кассир №2', role: 'kassir', cashbox: 'kassa2', password: 'kassa123' },
  kassa3: { name: 'Кассир №3', role: 'kassir', cashbox: 'kassa3', password: 'kassa123' },
  kassa_boz: { name: 'Кассири бозшумор', role: 'kassir', cashbox: 'kassa_boz', password: 'kassa123' },
  kaznachey: { name: 'Хазинашинос', role: 'viewer', password: 'view123' },
};

function seedDefaultUsers() {
  const users = {};
  Object.entries(DEFAULT_USERS_SEED).forEach(([key, u]) => {
    users[key] = {
      name: u.name,
      role: u.role,
      ...(u.cashbox ? { cashbox: u.cashbox } : {}),
      passwordHash: bcrypt.hashSync(u.password, 10),
    };
  });
  return { users };
}

if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(seedDefaultUsers()));
} else {
  // File exists but may be empty/null (e.g. a fresh Volume, or an old
  // deploy that never got past the removed client-side bootstrap step).
  try {
    const existing = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (!existing || !existing.users || Object.keys(existing.users).length === 0) {
      fs.writeFileSync(DATA_FILE, JSON.stringify(seedDefaultUsers()));
    }
  } catch (e) {
    // Corrupt/unreadable file — don't silently overwrite real data; log
    // and let readState() surface the parse error on first request.
    console.error('state.json could not be parsed at startup:', e.message);
  }
}

app.use(express.json({ limit: '5mb' }));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --- storage helpers -------------------------------------------------

let writeQueue = Promise.resolve();

function readState() {
  const raw = fs.readFileSync(DATA_FILE, 'utf8');
  return JSON.parse(raw);
}

function writeState(state) {
  writeQueue = writeQueue.then(
    () =>
      new Promise((resolve, reject) => {
        fs.writeFile(DATA_FILE, JSON.stringify(state), (err) => (err ? reject(err) : resolve()));
      })
  );
  return writeQueue;
}

// Hash any plain-text `password` field found on a user record, in place.
// Returns true if anything changed (so callers know whether to persist).
function migrateUsers(state) {
  if (!state || !state.users) return false;
  let changed = false;
  Object.values(state.users).forEach((u) => {
    if (u && u.password && !u.passwordHash) {
      u.passwordHash = bcrypt.hashSync(String(u.password), 10);
      delete u.password;
      changed = true;
    }
  });
  return changed;
}

// Never let a password or password hash leave the server in an API response.
function stripSecrets(state) {
  const clone = JSON.parse(JSON.stringify(state));
  if (clone && clone.users) {
    Object.values(clone.users).forEach((u) => {
      delete u.password;
      delete u.passwordHash;
    });
  }
  return clone;
}

// --- sessions (simple in-memory token store) --------------------------

const sessions = new Map(); // token -> { username, role, cashbox, ts }
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

function issueToken(username, u) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { username, role: u.role, cashbox: u.cashbox || null, ts: Date.now() });
  return token;
}

function getSession(req) {
  const token = req.headers['x-session-token'];
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() - s.ts > SESSION_TTL_MS) {
    sessions.delete(token);
    return null;
  }
  return s;
}

// Require a valid session for anything that touches full account data.
// Any logged-in user (any role) may read/write shared state; role-specific
// restrictions are enforced in the UI, but at minimum this stops anonymous
// visitors from reading balances or overwriting the database.
function requireAuth(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  req.session = session;
  next();
}

// --- login rate limiting (basic brute-force protection) ----------------
// Keyed by IP + attempted username so one bad actor can't lock out a
// legitimate user, but repeated guesses against one account/IP get slowed.
const loginAttempts = new Map(); // key -> { count, firstTs, lockedUntil }
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

function loginRateLimitKey(req, username) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  return `${ip}:${username || ''}`;
}

function isLoginLocked(key) {
  const rec = loginAttempts.get(key);
  if (!rec) return false;
  if (rec.lockedUntil && Date.now() < rec.lockedUntil) return true;
  if (rec.lockedUntil && Date.now() >= rec.lockedUntil) {
    loginAttempts.delete(key);
    return false;
  }
  return false;
}

function registerFailedLogin(key) {
  const now = Date.now();
  let rec = loginAttempts.get(key);
  if (!rec || now - rec.firstTs > LOGIN_WINDOW_MS) {
    rec = { count: 0, firstTs: now, lockedUntil: null };
  }
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_ATTEMPTS) {
    rec.lockedUntil = now + LOGIN_LOCKOUT_MS;
  }
  loginAttempts.set(key, rec);
}

function clearLoginAttempts(key) {
  loginAttempts.delete(key);
}

// --- state read/write --------------------------------------------------

// Everything below touches full account data (balances, ledgers, account
// numbers, requests, journal) and requires a valid session.
app.get('/api/state', requireAuth, (req, res) => {
  try {
    const state = readState();
    if (state && migrateUsers(state)) writeState(state);
    res.json({ value: state ? stripSecrets(state) : state });
  } catch (e) {
    console.error('Read error:', e);
    res.status(500).json({ error: 'read_failed' });
  }
});

app.post('/api/state', requireAuth, async (req, res) => {
  try {
    const incoming = req.body;
    const current = readState();
    // The client never has password hashes to send back, so re-attach the
    // ones already on disk for any user that still exists. Any brand-new
    // user the client just created (e.g. a new cashbox login) still has a
    // plain-text starter password at this point — migrateUsers() below
    // hashes it before it's ever written to disk.
    if (incoming && incoming.users) {
      Object.keys(incoming.users).forEach((key) => {
        if (current && current.users && current.users[key] && current.users[key].passwordHash) {
          incoming.users[key].passwordHash = current.users[key].passwordHash;
          delete incoming.users[key].password;
        }
      });
      migrateUsers(incoming);
    }
    await writeState(incoming);
    res.json({ ok: true });
  } catch (e) {
    console.error('Write error:', e);
    res.status(500).json({ error: 'write_failed' });
  }
});

// --- auth ---------------------------------------------------------------

app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    const rlKey = loginRateLimitKey(req, username);
    if (isLoginLocked(rlKey)) {
      return res.status(429).json({ error: 'too_many_attempts' });
    }
    const state = readState();
    if (!state || !state.users || !state.users[username]) {
      registerFailedLogin(rlKey);
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    if (migrateUsers(state)) writeState(state);
    const u = state.users[username];
    if (!u.passwordHash || !bcrypt.compareSync(String(password || ''), u.passwordHash)) {
      registerFailedLogin(rlKey);
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    clearLoginAttempts(rlKey);
    const token = issueToken(username, u);
    res.json({ ok: true, token, user: { key: username, name: u.name, role: u.role, cashbox: u.cashbox || null } });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'login_failed' });
  }
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

app.post('/api/change-password', async (req, res) => {
  try {
    const session = getSession(req);
    if (!session) return res.status(401).json({ error: 'unauthorized' });
    const { currentPassword, newPassword } = req.body || {};
    if (!newPassword || String(newPassword).length < 4) {
      return res.status(400).json({ error: 'weak_password' });
    }
    const state = readState();
    const u = state.users && state.users[session.username];
    if (!u) return res.status(404).json({ error: 'not_found' });
    if (!u.passwordHash || !bcrypt.compareSync(String(currentPassword || ''), u.passwordHash)) {
      return res.status(401).json({ error: 'wrong_current' });
    }
    u.passwordHash = bcrypt.hashSync(String(newPassword), 10);
    await writeState(state);
    res.json({ ok: true });
  } catch (e) {
    console.error('Change-password error:', e);
    res.status(500).json({ error: 'failed' });
  }
});

app.post('/api/admin-set-password', async (req, res) => {
  try {
    const session = getSession(req);
    if (!session || session.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    const { targetUsername, newPassword } = req.body || {};
    if (!newPassword || String(newPassword).length < 4) {
      return res.status(400).json({ error: 'weak_password' });
    }
    const state = readState();
    const u = state.users && state.users[targetUsername];
    if (!u) return res.status(404).json({ error: 'not_found' });
    u.passwordHash = bcrypt.hashSync(String(newPassword), 10);
    await writeState(state);
    res.json({ ok: true });
  } catch (e) {
    console.error('Admin-set-password error:', e);
    res.status(500).json({ error: 'failed' });
  }
});

// --- one-time emergency recovery ---------------------------------------
// Disabled unless the EMERGENCY_RESET_KEY environment variable is set on
// the server (e.g. in Railway's "Variables" tab). Nothing in this source
// file grants access by itself, so committing this file to a repo (even a
// public one) can't leak a working reset key. After using it, remove the
// environment variable so the endpoint goes dark again.
app.get('/api/emergency-reset-admin', async (req, res) => {
  try {
    const configuredKey = process.env.EMERGENCY_RESET_KEY;
    if (!configuredKey) return res.status(404).send('Not found');
    if (req.query.key !== configuredKey) return res.status(403).send('Forbidden');
    const state = readState();
    if (!state || !state.users || !state.users.admin) return res.status(404).send('admin user not found');
    const tempPassword = crypto.randomBytes(9).toString('base64url');
    state.users.admin.passwordHash = bcrypt.hashSync(tempPassword, 10);
    delete state.users.admin.password;
    await writeState(state);
    console.log(`Emergency admin reset used. Temporary password: ${tempPassword}`);
    res.send(
      'OK: admin password has been reset. The new temporary password was printed to the server logs (Railway → Deployments → View Logs) — it is not shown here. ' +
      'Log in with it, change it immediately from the Users page, then remove the EMERGENCY_RESET_KEY variable from your hosting settings.'
    );
  } catch (e) {
    console.error('Emergency reset error:', e);
    res.status(500).send('failed');
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Azim Core server running on port ${PORT}`);
});
