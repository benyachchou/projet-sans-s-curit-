const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { DATABASE_URL } = process.env;

const db = new sqlite3.Database(DATABASE_URL || path.join(__dirname, '..', 'data.sqlite'));

db.serialize(() => {
  // Utilisateurs
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','user'))
    )
  `);

  // Ressources
  db.run(`
    CREATE TABLE IF NOT EXISTS resources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      owner_id INTEGER,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    )
  `);

  // Évolution du schéma: ajout des colonnes si absentes
  // Ajout des colonnes pour les ressources typées (type, metadata)
  db.all(`PRAGMA table_info(resources)`, (err, cols) => {
    if (err) return;
    const names = (cols || []).map(c => c.name);
    if (!names.includes('type')) {
      db.run(`ALTER TABLE resources ADD COLUMN type TEXT`);
    }
    if (!names.includes('metadata')) {
      db.run(`ALTER TABLE resources ADD COLUMN metadata TEXT`);
    }
  });
  // Indexes pour performance et unicité CVE
  db.run(`CREATE INDEX IF NOT EXISTS idx_resources_type_name ON resources(type, name)`);
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_resources_cve_unique ON resources(name) WHERE type = 'cve'`);

  // Audit logs (admin actions)
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      details TEXT,
      created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      FOREIGN KEY(actor_id) REFERENCES users(id)
    )
  `);
});

module.exports = db;