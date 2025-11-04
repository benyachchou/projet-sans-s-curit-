const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { validationResult } = require('express-validator');
const { registerSchema, loginSchema } = require('../validators/schemas');
const { requireAuth, requireRole } = require('../middleware/auth');
const { ROLES } = require('../utils/roles');
const { logAudit } = require('../utils/audit');

const router = express.Router();

router.post('/register', registerSchema, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password, role } = req.body;
  const rounds = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

  bcrypt.hash(password, rounds).then((hash) => {
    const r = role || ROLES.USER;
    const stmt = `INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)`;
    db.run(stmt, [username, email, hash, r], function (err) {
      if (err) {
        if (String(err.message || '').includes('UNIQUE')) {
          return res.status(409).json({ error: 'Username or email already exists' });
        }
        return res.status(500).json({ error: 'DB error' });
      }
      return res.status(201).json({ id: this.lastID, username, email, role: r });
    });
  });
});

router.post('/login', loginSchema, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const exp = parseInt(process.env.JWT_EXPIRES_IN || '900', 10); // seconds
    const token = jwt.sign(
      { sub: user.id, role: user.role, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: exp }
    );
    return res.json({ access_token: token, token_type: 'Bearer', expires_in: exp });
  });
});

router.get('/profile', requireAuth, (req, res) => {
  const id = req.user.id;
  db.get(`SELECT id, username, email, role FROM users WHERE id = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'User not found' });
    return res.json(row);
  });
});

// Admin: liste tous les utilisateurs
router.get('/users', requireAuth, requireRole(ROLES.ADMIN), (req, res) => {
  const page = Math.max(parseInt(req.query.page || '1', 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 200);
  const offset = (page - 1) * limit;

  const listSql = `
    SELECT id, username, email, role
    FROM users
    ORDER BY id ASC
    LIMIT ? OFFSET ?
  `;
  db.all(listSql, [limit, offset], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    db.get(`SELECT COUNT(*) AS total FROM users`, [], (cntErr, cntRow) => {
      if (cntErr) return res.status(500).json({ error: 'DB error' });
      const total_count = Number(cntRow?.total || 0);
      const has_next = offset + rows.length < total_count;
      return res.json({ page, limit, count: rows.length, total_count, has_next, items: rows });
    });
  });
});

// Admin: supprimer un utilisateur par id
router.delete('/users/:id', requireAuth, requireRole(ROLES.ADMIN), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });
  const cascade = String(req.query.cascade || '').toLowerCase() === 'true';

  const deleteUser = () =>
    new Promise((resolve) => {
      db.run(`DELETE FROM users WHERE id = ?`, [id], function (err) {
        if (err) return resolve({ ok: false, error: 'DB error' });
        if (this.changes === 0) return resolve({ ok: false, error: 'User not found', status: 404 });
        return resolve({ ok: true });
      });
    });

  const deleteResources = () =>
    new Promise((resolve) => {
      db.run(`DELETE FROM resources WHERE owner_id = ?`, [id], function (err) {
        if (err) return resolve({ ok: false, error: 'DB error' });
        return resolve({ ok: true, deleted: this.changes });
      });
    });

  try {
    if (cascade) await deleteResources();
    const result = await deleteUser();
    if (!result.ok) return res.status(result.status || 500).json({ error: result.error });
    await logAudit({ actorId: req.user.id, action: 'delete_user', entityType: 'user', entityId: id, details: { cascade } });
    return res.status(204).send();
  } catch (e) {
    return res.status(500).json({ error: 'Internal error' });
  }
});

// Admin: supprimer un utilisateur par username (fallback pratique)
router.delete('/users/by-username/:username', requireAuth, requireRole(ROLES.ADMIN), (req, res) => {
  const username = String(req.params.username || '').trim();
  if (!username) return res.status(400).json({ error: 'Invalid username' });

  db.run(`DELETE FROM users WHERE username = ?`, [username], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    logAudit({ actorId: req.user.id, action: 'delete_user', entityType: 'user', entityId: username }).then(() => {});
    return res.status(204).send();
  });
});

module.exports = router;