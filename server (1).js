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

const
