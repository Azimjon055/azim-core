// Azim Core — backend server
// Serves the app (index.html) and stores all data as one JSON blob on disk,
// so every computer that opens this server's URL shares the same data.

const express = require('express');
const fs = require('fs');
const path = require('path');

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

// Simple write queue so two saves arriving at the same instant don't corrupt the file.
let writeQueue = Promise.resolve();

app.get('/api/state', (req, res) => {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const value = JSON.parse(raw);
    res.json({ value });
  } catch (e) {
    console.error('Read error:', e);
    res.status(500).json({ error: 'read_failed' });
  }
});

app.post('/api/state', (req, res) => {
  writeQueue = writeQueue
    .then(
      () =>
        new Promise((resolve, reject) => {
          fs.writeFile(DATA_FILE, JSON.stringify(req.body), (err) => {
            if (err) reject(err);
            else resolve();
          });
        })
    )
    .then(() => res.json({ ok: true }))
    .catch((e) => {
      console.error('Write error:', e);
      res.status(500).json({ error: 'write_failed' });
    });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Azim Core server running on port ${PORT}`);
});
