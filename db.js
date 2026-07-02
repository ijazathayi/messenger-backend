/**
 * db.js — Database adapter
 *
 * LOCAL  dev : uses sqlite3 (file: messenger.db)
 * CLOUD  prod: uses Turso (@libsql/client) via TURSO_DATABASE_URL + TURSO_AUTH_TOKEN env vars
 *
 * The wrapper exposes the same .run / .get / .all / .serialize API
 * that the rest of the codebase already uses, so nothing else needs to change.
 */

// ── Detect environment ────────────────────────────────────────────────────────
const USE_TURSO = !!(process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN);

if (USE_TURSO) {
  // ── CLOUD: Turso ─────────────────────────────────────────────────────────
  const { createClient } = require('@libsql/client');

  const turso = createClient({
    url:       process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
  });

  // Thin compatibility wrapper — mirrors sqlite3's callback API
  const db = {
    _turso: turso,

    run(sql, params = [], cb) {
      turso.execute({ sql, args: params })
        .then(r  => cb && cb(null))
        .catch(e => cb && cb(e));
    },

    get(sql, params = [], cb) {
      turso.execute({ sql, args: params })
        .then(r  => cb && cb(null, r.rows[0] || undefined))
        .catch(e => cb && cb(e));
    },

    all(sql, params = [], cb) {
      turso.execute({ sql, args: params })
        .then(r  => cb && cb(null, r.rows))
        .catch(e => cb && cb(e));
    },

    // sqlite3 serialize() just runs the callback immediately
    serialize(cb) { cb && cb(); },
  };

  // Create tables on startup
  const schema = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      google_id TEXT UNIQUE,
      name TEXT,
      email TEXT UNIQUE,
      avatar TEXT,
      about TEXT,
      user_code TEXT UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER,
      receiver_id INTEGER,
      text TEXT,
      is_edited INTEGER DEFAULT 0,
      is_deleted INTEGER DEFAULT 0,
      attachment_url TEXT,
      attachment_type TEXT,
      status TEXT DEFAULT 'sent',
      deleted_by TEXT DEFAULT '[]',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS call_recordings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      caller_id INTEGER,
      receiver_id INTEGER,
      call_type TEXT,
      recording_url TEXT,
      duration_seconds INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
  ];

  (async () => {
    for (const sql of schema) {
      await turso.execute(sql).catch(e => console.warn('[DB] Schema warn:', e.message));
    }
    console.log('[DB] Connected to Turso cloud database.');
  })();

  module.exports = db;

} else {
  // ── LOCAL: sqlite3 ────────────────────────────────────────────────────────
  const sqlite3 = require('sqlite3').verbose();
  const path    = require('path');
  const dbPath  = path.resolve(__dirname, 'messenger.db');

  const db = new sqlite3.Database(dbPath, (err) => {
    if (err) { console.error('Error opening database', err.message); return; }
    console.log('[DB] Connected to local SQLite database.');

    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      google_id TEXT UNIQUE, name TEXT, email TEXT UNIQUE,
      avatar TEXT, about TEXT, user_code TEXT UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, () => {
      db.run(`ALTER TABLE users ADD COLUMN about TEXT`,     () => {});
      db.run(`ALTER TABLE users ADD COLUMN user_code TEXT`, () => {});
    });

    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER, receiver_id INTEGER, text TEXT,
      is_edited INTEGER DEFAULT 0, is_deleted INTEGER DEFAULT 0,
      attachment_url TEXT, attachment_type TEXT,
      status TEXT DEFAULT 'sent', deleted_by TEXT DEFAULT '[]',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, () => {
      db.run(`ALTER TABLE messages ADD COLUMN is_edited INTEGER DEFAULT 0`,     () => {});
      db.run(`ALTER TABLE messages ADD COLUMN is_deleted INTEGER DEFAULT 0`,    () => {});
      db.run(`ALTER TABLE messages ADD COLUMN attachment_url TEXT`,              () => {});
      db.run(`ALTER TABLE messages ADD COLUMN attachment_type TEXT`,             () => {});
      db.run(`ALTER TABLE messages ADD COLUMN status TEXT DEFAULT 'sent'`,       () => {});
      db.run(`ALTER TABLE messages ADD COLUMN deleted_by TEXT DEFAULT '[]'`,     () => {});
    });

    db.run(`CREATE TABLE IF NOT EXISTS call_recordings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      caller_id INTEGER, receiver_id INTEGER, call_type TEXT,
      recording_url TEXT, duration_seconds INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
  });

  module.exports = db;
}
