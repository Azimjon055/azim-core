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

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'state.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify(null));

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

// --- state read/write --------------------------------------------------

app.get('/api/state', (req, res) => {
  try {
    const state = readState();
    if (state && migrateUsers(state)) writeState(state);
    res.json({ value: state ? stripSecrets(state) : state });
  } catch (e) {
    console.error('Read error:', e);
    res.status(500).json({ error: 'read_failed' });
  }
});

app.post('/api/state', async (req, res) => {
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
    const state = readState();
    if (!state || !state.users || !state.users[username]) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    if (migrateUsers(state)) writeState(state);
    const u = state.users[username];
    if (!u.passwordHash || !bcrypt.compareSync(String(password || ''), u.passwordHash)) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
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

// --- one-time emergency recovery (remove this block once you've used it) ---
app.get('/api/emergency-reset-admin', async (req, res) => {
  try {
    if (req.query.key !== 'VaslBonk2026Reset') return res.status(403).send('Forbidden');
    const state = readState();
    if (!state || !state.users || !state.users.admin) return res.status(404).send('admin user not found');
    state.users.admin.passwordHash = bcrypt.hashSync('admin123', 10);
    delete state.users.admin.password;
    await writeState(state);
    res.send('OK: admin password reset to admin123. Log in now, then change it immediately from the Users page. Afterwards, please remove this endpoint from server.js for security.');
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
