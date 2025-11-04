const express = require('express');
const db = require('../db');
const { validationResult } = require('express-validator');
const { requireAuth, requireRole, ROLES } = require('../middleware/auth');
const { createResourceSchema, updateResourceSchema, createCveSchema, updateCveSchema, importCveSchema, importBulkCveSchema } = require('../validators/schemas');
const { getCveFromCveOrg } = require('../services/cveProvider');
const { getNvdById, getNvdRange } = require('../services/nvdProvider');
const sanitizeHtml = require('sanitize-html');

const router = express.Router();

const safeHtml = (html) =>
  sanitizeHtml(String(html || ''), {
    allowedTags: ['a', 'p', 'ul', 'ol', 'li', 'em', 'strong', 'code', 'pre', 'br'],
    allowedAttributes: { a: ['href', 'rel', 'target'] },
    transformTags: { a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' }) }
  }) || null;

// List resources avec filtres et pagination:
// - Admin: toutes
// - User: seulement les siennes
router.get('/resources', requireAuth, (req, res) => {
  const { type, q } = req.query;
  const page = Math.max(parseInt(req.query.page || '1', 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 100);
  const offset = (page - 1) * limit;

  const params = [];
  const where = [];

  if (type) {
    where.push(`r.type = ?`);
    params.push(type);
  }
  if (q) {
    where.push(`LOWER(r.name) LIKE ?`);
    params.push(`%${String(q).toLowerCase()}%`);
  }

  // Portée utilisateur
  if (req.user.role !== 'admin') {
    where.push(`r.owner_id = ?`);
    params.push(req.user.id);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const baseAdminSelect = `
    SELECT r.id, r.name, r.type, r.metadata, r.owner_id, u.username AS owner_username
    FROM resources r
    LEFT JOIN users u ON r.owner_id = u.id
    ${whereSql}
    ORDER BY r.id DESC
    LIMIT ? OFFSET ?
  `;
  const baseUserSelect = `
    SELECT r.id, r.name, r.type, r.metadata, r.owner_id
    FROM resources r
    ${whereSql}
    ORDER BY r.id DESC
    LIMIT ? OFFSET ?
  `;

  const sql = req.user.role === 'admin' ? baseAdminSelect : baseUserSelect;
  const finalParams = params.concat([limit, offset]);

  db.all(sql, finalParams, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    // Parse metadata JSON si présent
    const data = (rows || []).map(r => ({
      ...r,
      metadata: r.metadata ? safeParseJson(r.metadata) : null
    }));
    return res.json({ page, limit, count: data.length, items: data });
  });
});

function safeParseJson(str) {
  try { return JSON.parse(str); } catch (_) { return null; }
}

// Create a resource (assignée à l'utilisateur authentifié)
router.post('/resources', requireAuth, createResourceSchema, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, type, metadata } = req.body;
  const ownerId = req.user.id;
  const metaStr = metadata ? JSON.stringify(metadata) : null;

  const stmt = `INSERT INTO resources (name, owner_id, type, metadata) VALUES (?,?,?,?)`;
  db.run(stmt, [name, ownerId, type || null, metaStr], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    return res.status(201).json({
      id: this.lastID,
      name,
      owner_id: ownerId,
      type: type || null,
      metadata: metadata || null
    });
  });
});

// Mise à jour d'une ressource (propriétaire ou admin)
router.patch('/resources/:id', requireAuth, updateResourceSchema, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

  db.get(`SELECT * FROM resources WHERE id = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Resource not found' });

    if (req.user.role !== 'admin' && row.owner_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden: not owner' });
    }

    const fields = [];
    const params = [];

    if (typeof req.body.name === 'string') {
      fields.push(`name = ?`);
      params.push(req.body.name);
    }
    if (typeof req.body.type === 'string') {
      fields.push(`type = ?`);
      params.push(req.body.type);
    }
    if (req.body.metadata !== undefined) {
      fields.push(`metadata = ?`);
      params.push(req.body.metadata ? JSON.stringify(req.body.metadata) : null);
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    params.push(id);

    db.run(`UPDATE resources SET ${fields.join(', ')} WHERE id = ?`, params, function (updErr) {
      if (updErr) return res.status(500).json({ error: 'DB error' });
      return res.status(200).json({ updated: this.changes });
    });
  });
});

// Suppression (admin: tout; user: seulement ses ressources)
router.delete('/resources/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

  db.get(`SELECT * FROM resources WHERE id = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Resource not found' });

    if (req.user.role !== 'admin' && row.owner_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden: not owner' });
    }

    db.run(`DELETE FROM resources WHERE id = ?`, [id], function (delErr) {
      if (delErr) return res.status(500).json({ error: 'DB error' });
      return res.status(204).send();
    });
  });
});

// Création d'une CVE (admin uniquement)
router.post('/cves', requireAuth, requireRole(ROLES.ADMIN), createCveSchema, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const {
    cve_id, title, description, severity, cvss_score,
    affected_products, references, recommendation,
    published_at, last_modified
  } = req.body;

  const ownerId = req.user.id;
  const normalizedCveId = String(cve_id).toUpperCase();

  // Empêcher les doublons: même CVE (name) déjà existante
  db.get(`SELECT id FROM resources WHERE type = 'cve' AND name = ?`, [normalizedCveId], (err, existing) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (existing) return res.status(409).json({ error: 'CVE already exists' });

    const metadata = {
      cve_id: normalizedCveId,
      title,
      description,
      severity,
      cvss_score: typeof cvss_score === 'number' ? cvss_score : null,
      affected_products: Array.isArray(affected_products) ? affected_products : [],
      // normaliser et dédupliquer les références avant stockage
      references: Array.isArray(references) ? normalizeReferences(references) : [],
      recommendation,
      published_at: published_at || null,
      last_modified: last_modified || null,
      description_html: safeHtml(req.body.description_html || null)
    };

    db.run(
      `INSERT INTO resources (name, owner_id, type, metadata) VALUES (?,?,?,?)`,
      [normalizedCveId, ownerId, 'cve', JSON.stringify(metadata)],
      function (insErr) {
        if (insErr) {
          if (String(insErr.message || '').includes('UNIQUE')) {
            return res.status(409).json({ error: 'CVE already exists' });
          }
          return res.status(500).json({ error: 'DB error' });
        }
        const { logAudit } = require('../utils/audit');
        logAudit({ actorId: ownerId, action: 'create_cve', entityType: 'cve', entityId: normalizedCveId }).then(() => {});
        return res.status(201).json({ id: this.lastID, ...metadata, owner_id: ownerId });
      }
    );
  });
});

// Liste des CVE (auth requis, visible par tous les rôles)
router.get('/cves', requireAuth, (req, res) => {
  const { cve_id, severity, q } = req.query;
  const page = Math.max(parseInt(req.query.page || '1', 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 100);
  const offset = (page - 1) * limit;

  const where = ['r.type = ?'];
  const params = ['cve'];

  if (cve_id) {
    where.push('UPPER(r.name) = ?');
    params.push(String(cve_id).toUpperCase());
  }
  if (q) {
    where.push('LOWER(r.metadata) LIKE ?');
    params.push(`%${String(q).toLowerCase()}%`);
  }

  const whereSql = `WHERE ${where.join(' AND ')}`;

  const baseAdminSelect = `
    SELECT r.id, r.name, r.metadata, r.owner_id, u.username AS owner_username
    FROM resources r
    LEFT JOIN users u ON r.owner_id = u.id
    ${whereSql}
    ORDER BY r.id DESC
    LIMIT ? OFFSET ?
  `;
  const baseUserSelect = `
    SELECT r.id, r.name, r.metadata, r.owner_id
    FROM resources r
    ${whereSql}
    ORDER BY r.id DESC
    LIMIT ? OFFSET ?
  `;

  const sql = req.user.role === ROLES.ADMIN ? baseAdminSelect : baseUserSelect;
  const finalParams = params.concat([limit, offset]);

  db.all(sql, finalParams, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    let items = (rows || []).map(r => {
      const meta = (() => { try { return JSON.parse(r.metadata); } catch { return {}; } })();

      // sanitize references pour la sortie
      const refs = normalizeReferences(Array.isArray(meta.references) ? meta.references : []);

      return {
        id: r.id,
        owner_id: r.owner_id,
        owner_username: r.owner_username,
        cve_id: meta.cve_id,
        title: meta.title,
        description: meta.description,
        description_html: meta.description_html,
        severity: meta.severity,
        cvss_score: meta.cvss_score,
        affected_products: meta.affected_products,
        references: refs,
        recommendation: meta.recommendation,
        published_at: meta.published_at,
        last_modified: meta.last_modified
      };
    });

    if (severity) {
      const sev = String(severity).toLowerCase();
      items = items.filter(it => String(it.severity || '').toLowerCase() === sev);
    }

    // Calcule total_count avec le même WHERE, sans LIMIT/OFFSET
    const countSql = `
      SELECT COUNT(*) AS total
      FROM resources r
      ${req.user.role === ROLES.ADMIN ? 'LEFT JOIN users u ON r.owner_id = u.id' : ''}
      ${whereSql}
    `;
    db.get(countSql, params, (cntErr, cntRow) => {
      if (cntErr) return res.status(500).json({ error: 'DB error' });
      const total_count = Number(cntRow?.total || 0);
      const has_next = offset + items.length < total_count;
      return res.json({ page, limit, count: items.length, total_count, has_next, items });
    });
  });
});

// Détail d'une CVE
// Route: GET /api/cves/:id
router.get('/cves/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

  db.get(
    `SELECT r.id, r.name, r.metadata, r.owner_id, u.username AS owner_username
     FROM resources r
     LEFT JOIN users u ON r.owner_id = u.id
     WHERE r.id = ? AND r.type = 'cve'`,
    [id],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (!row) return res.status(404).json({ error: 'Resource not found' });

      const meta = (() => { try { return JSON.parse(row.metadata); } catch { return {}; } })();
      const refs = Array.isArray(meta.references) ? normalizeReferences(meta.references) : [];

      return res.json({
        id: row.id,
        owner_id: row.owner_id,
        owner_username: row.owner_username,
        cve_id: meta.cve_id,
        title: meta.title,
        description: meta.description,
        description_html: safeHtml(meta.description_html),
        severity: meta.severity,
        cvss_score: meta.cvss_score,
        affected_products: meta.affected_products,
        references: refs,
        recommendation: meta.recommendation,
        published_at: meta.published_at,
        last_modified: meta.last_modified
      });
    }
  );
});

// Récupérer une CVE stockée par son cve_id (name)
// Route: GET /api/cves/by-id/:cve_id
router.get('/cves/by-id/:cve_id', requireAuth, (req, res) => {
  const cveId = String(req.params.cve_id || '').toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/i.test(cveId)) {
    return res.status(400).json({ error: 'Invalid CVE ID format' });
  }
  db.get(
    `SELECT id, name, metadata, owner_id FROM resources WHERE type = 'cve' AND name = ?`,
    [cveId],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (!row) return res.status(404).json({ error: 'Resource not found' });

      const meta = (() => { try { return JSON.parse(row.metadata); } catch { return {}; } })();
      const refs = Array.isArray(meta.references) ? normalizeReferences(meta.references) : [];

      return res.json({
        id: row.id,
        owner_id: row.owner_id,
        cve_id: meta.cve_id,
        title: meta.title,
        description: meta.description,
        description_html: safeHtml(meta.description_html),
        severity: meta.severity,
        cvss_score: meta.cvss_score,
        affected_products: meta.affected_products,
        references: refs,
        recommendation: meta.recommendation,
        published_at: meta.published_at,
        last_modified: meta.last_modified
      });
    }
  );
});

// Mise à jour d'une CVE (admin uniquement)
router.patch('/cves/:id', requireAuth, requireRole(ROLES.ADMIN), updateCveSchema, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

  db.get(`SELECT * FROM resources WHERE id = ? AND type = 'cve'`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Resource not found' });

    const current = safeParseJson(row.metadata) || {};
    const next = {
      ...current,
      cve_id: req.body.cve_id ?? current.cve_id,
      title: req.body.title ?? current.title,
      description: req.body.description ?? current.description,
      severity: req.body.severity ?? current.severity,
      cvss_score: req.body.cvss_score ?? current.cvss_score,
      affected_products: req.body.affected_products ?? current.affected_products,
      // si fourni, assainir les références à l'écriture
      references: Array.isArray(req.body.references)
        ? normalizeReferences(req.body.references)
        : current.references,
      recommendation: req.body.recommendation ?? current.recommendation,
      published_at: req.body.published_at ?? current.published_at,
      last_modified: req.body.last_modified ?? current.last_modified
    };

    const newName = next.cve_id || row.name;

    db.run(
      `UPDATE resources SET name = ?, metadata = ? WHERE id = ?`,
      [newName, JSON.stringify(next), id],
      function (updErr) {
        if (updErr) return res.status(500).json({ error: 'DB error' });
        return res.status(200).json({ updated: this.changes });
      }
    );
  });
});

// Suppression d'une CVE (admin uniquement)
router.delete('/cves/:id', requireAuth, requireRole(ROLES.ADMIN), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

  db.run(`DELETE FROM resources WHERE id = ? AND type = 'cve'`, [id], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Resource not found' });
    const { logAudit } = require('../utils/audit');
    logAudit({ actorId: req.user.id, action: 'delete_cve', entityType: 'cve', entityId: id }).then(() => {});
    return res.status(204).send();
  });
});

// Récupération "live" d'une CVE depuis CVE.org (sans stockage)
router.get('/cves/:cve_id/external', requireAuth, async (req, res) => {
  const cveId = String(req.params.cve_id || '').toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/i.test(cveId)) {
    return res.status(400).json({ error: 'Invalid CVE ID format' });
  }
  try {
    const data = await getCveFromCveOrg(cveId);
    const refs = Array.isArray(data.references) ? normalizeReferences(data.references) : [];
    return res.json({ ...data, references: refs, description_html: safeHtml(data.description_html) });
  } catch (e) {
    if (e.status === 404) return res.status(404).json({ error: 'CVE not found externally' });
    return res.status(502).json({ error: 'Upstream error', detail: String(e.message || e) });
  }
});

// Importer et stocker une CVE (admin)
// - Vérifie l'unicité (type='cve' + name=cve_id)
// - Mappe depuis l'API externe
router.post('/cves/import', requireAuth, requireRole(ROLES.ADMIN), importCveSchema, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const cveId = String(req.body.cve_id).toUpperCase();

  db.get(`SELECT id FROM resources WHERE type = 'cve' AND name = ?`, [cveId], async (err, existing) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (existing) return res.status(409).json({ error: 'CVE already exists' });

    try {
      const meta = await getCveFromCveOrg(cveId);
      meta.description_html = safeHtml(meta.description_html);
      // assainir les références importées avant stockage
      meta.references = Array.isArray(meta.references) ? normalizeReferences(meta.references) : [];
      const ownerId = req.user.id;
      db.run(
        `INSERT INTO resources (name, owner_id, type, metadata) VALUES (?,?,?,?)`,
        [cveId, ownerId, 'cve', JSON.stringify(meta)],
        function (insErr) {
          if (insErr) {
            if (String(insErr.message || '').includes('UNIQUE')) {
              return res.status(409).json({ error: 'CVE already exists' });
            }
            return res.status(500).json({ error: 'DB error' });
          }
          const { logAudit } = require('../utils/audit');
          logAudit({ actorId: ownerId, action: 'import_cve', entityType: 'cve', entityId: cveId }).then(() => {});
          return res.status(201).json({ id: this.lastID, ...meta, owner_id: ownerId });
        }
      );
    } catch (e) {
      if (e.status === 404) return res.status(404).json({ error: 'CVE not found externally' });
      return res.status(502).json({ error: 'Upstream error', detail: String(e.message || e) });
    }
  });
});

// Récupérer une CVE stockée par son cve_id (name)
router.get('/cves/by-id/:cve_id', requireAuth, (req, res) => {
  const cveId = String(req.params.cve_id || '').toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/i.test(cveId)) {
    return res.status(400).json({ error: 'Invalid CVE ID format' });
  }
  db.get(
    `SELECT id, name, metadata, owner_id FROM resources WHERE type = 'cve' AND name = ?`,
    [cveId],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (!row) return res.status(404).json({ error: 'Resource not found' });
      const meta = (() => { try { return JSON.parse(row.metadata); } catch { return {}; } })();
      const refs = Array.isArray(meta.references) ? normalizeReferences(meta.references) : [];
      return res.json({
        id: row.id,
        owner_id: row.owner_id,
        cve_id: meta.cve_id,
        title: meta.title,
        description: meta.description,
        description_html: meta.description_html,
        severity: meta.severity,
        cvss_score: meta.cvss_score,
        affected_products: meta.affected_products,
        references: refs,
        recommendation: meta.recommendation,
        published_at: meta.published_at,
        last_modified: meta.last_modified
      });
    }
  );
});

// Import / Synchronisation d’une CVE (admin): upsert si existe
router.post('/cves/sync', requireAuth, requireRole(ROLES.ADMIN), importCveSchema, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const cveId = String(req.body.cve_id).toUpperCase();

  try {
    const meta = await getCveFromCveOrg(cveId);
    meta.description_html = safeHtml(meta.description_html);
    meta.references = Array.isArray(meta.references) ? normalizeReferences(meta.references) : [];
    db.get(`SELECT id FROM resources WHERE type = 'cve' AND name = ?`, [cveId], (err, existing) => {
      if (err) return res.status(500).json({ error: 'DB error' });

      if (existing) {
        db.run(
          `UPDATE resources SET metadata = ? WHERE id = ?`,
          [JSON.stringify(meta), existing.id],
          function (updErr) {
            if (updErr) return res.status(500).json({ error: 'DB error' });
            const { logAudit } = require('../utils/audit');
            logAudit({ actorId: req.user.id, action: 'sync_cve', entityType: 'cve', entityId: cveId, details: { updated: this.changes } }).then(() => {});
            return res.status(200).json({ id: existing.id, updated: this.changes });
          }
        );
      } else {
        const ownerId = req.user.id;
        db.run(
          `INSERT INTO resources (name, owner_id, type, metadata) VALUES (?,?,?,?)`,
          [cveId, ownerId, 'cve', JSON.stringify(meta)],
          function (insErr) {
            if (insErr) return res.status(500).json({ error: 'DB error' });
            const { logAudit } = require('../utils/audit');
            logAudit({ actorId: req.user.id, action: 'sync_cve', entityType: 'cve', entityId: cveId, details: { created: this.lastID } }).then(() => {});
            return res.status(201).json({ id: this.lastID, owner_id: ownerId, ...meta });
          }
        );
      }
    });
  } catch (e) {
    if (e.status === 404) return res.status(404).json({ error: 'CVE not found externally' });
    return res.status(502).json({ error: 'Upstream error', detail: String(e.message || e) });
  }
});

// Import en masse depuis NVD (admin): par année OU par plage de dates (pubStartDate/pubEndDate)
router.post('/cves/import-bulk', requireAuth, requireRole(ROLES.ADMIN), importBulkCveSchema, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const year = req.body.year ? Number(req.body.year) : null;
  const resultsPerPage = req.body.resultsPerPage ?? 2000;
  const delayMs = req.body.delayMs ?? 1500;

  const pubStartDate = req.body.pubStartDate || (year ? `${year}-01-01T00:00:00.000Z` : null);
  const pubEndDate = req.body.pubEndDate || (year ? `${year}-12-31T23:59:59.999Z` : null);

  if (!pubStartDate || !pubEndDate) {
    return res.status(400).json({ error: 'Provide either year or pubStartDate/pubEndDate' });
  }

  // Découper en fenêtres ≤ 120 jours si la période est grande (contrainte NVD)
  function makeChunks(startIso, endIso, maxDays = 120) {
    const chunks = [];
    const start = new Date(startIso);
    const end = new Date(endIso);
    const stepMs = maxDays * 24 * 60 * 60 * 1000;

    let curStart = new Date(start);
    while (curStart <= end) {
      const curEnd = new Date(Math.min(curStart.getTime() + stepMs - 1, end.getTime()));
      chunks.push({
        pubStartDate: curStart.toISOString(),
        pubEndDate: curEnd.toISOString(),
      });
      curStart = new Date(curEnd.getTime() + 1);
    }
    return chunks;
  }

  try {
    const ranges = year
      ? makeChunks(pubStartDate, pubEndDate, 120)
      : makeChunks(pubStartDate, pubEndDate, 120); // même logique pour une plage très large

    let importedCount = 0;
    let created = 0;
    let updated = 0;
    const ownerId = req.user.id;
    const windows = [];

    for (const r of ranges) {
      windows.push(r);
      const items = await getNvdRange({
        pubStartDate: r.pubStartDate,
        pubEndDate: r.pubEndDate,
        resultsPerPage,
        delayMs,
      });

      importedCount += items.length;

      for (const meta of items) {
        const cveId = meta.cve_id;

        // upsert
        // On attend la fin de chaque opération DB avant de continuer
        /* eslint-disable no-await-in-loop */
        await new Promise((resolve) => {
          db.get(`SELECT id FROM resources WHERE type = 'cve' AND name = ?`, [cveId], (err, existing) => {
            if (err) return resolve();
            if (existing) {
              db.run(
                `UPDATE resources SET metadata = ? WHERE id = ?`,
                [JSON.stringify(meta), existing.id],
                function () {
                  updated += this.changes ? 1 : 0;
                  resolve();
                }
              );
            } else {
              db.run(
                `INSERT INTO resources (name, owner_id, type, metadata) VALUES (?,?,?,?)`,
                [cveId, ownerId, 'cve', JSON.stringify(meta)],
                function () {
                  created += this.lastID ? 1 : 0;
                  resolve();
                }
              );
            }
          });
        });
        /* eslint-enable no-await-in-loop */
      }
    }

    return res.status(200).json({
      imported_count: importedCount,
      created,
      updated,
      windows_count: windows.length,
      period: { pubStartDate, pubEndDate },
    });
  } catch (e) {
    // Ne pas retourner 404 pour "aucun résultat", renvoyer 200 avec imported_count: 0
    if (e.status === 404) {
      return res.status(200).json({
        imported_count: 0,
        created: 0,
        updated: 0,
        period: { pubStartDate, pubEndDate },
      });
    }
    return res.status(502).json({ error: 'NVD upstream error', detail: String(e.message || e) });
  }
});

// Récupération "live" d’une CVE via NVD, sans stockage
// Route: GET /api/cves/nvd/:cve_id (live NVD)
router.get('/cves/nvd/:cve_id', requireAuth, async (req, res) => {
  const cveId = String(req.params.cve_id || '').toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/i.test(cveId)) {
    return res.status(400).json({ error: 'Invalid CVE ID format' });
  }
  try {
    const meta = await getNvdById(cveId);
    const refs = Array.isArray(meta.references) ? normalizeReferences(meta.references) : [];

    return res.json({
      cve_id: meta.cve_id,
      title: meta.title,
      description: meta.description,
      description_html: safeHtml(meta.description_html),
      severity: meta.severity,
      cvss_score: meta.cvss_score,
      affected_products: meta.affected_products,
      references: refs,
      recommendation: meta.recommendation,
      published_at: meta.published_at,
      last_modified: meta.last_modified
    });
  } catch (e) {
    if (e.status === 404) return res.status(404).json({ error: 'CVE not found in NVD' });
    return res.status(502).json({ error: 'NVD upstream error', detail: String(e.message || e) });
  }
});

// Normalisation des références (admin):
function normalizeUrl(u) {
  const s = String(u || '');
  // Retire uniquement les wrappers en début/fin (espaces, backticks, guillemets, chevrons)
  const trimmed = s.replace(/^[\s`"'<>]+|[\s`"'<>]+$/g, '');
  try {
    const parsed = new URL(trimmed);
    return parsed.toString();
  } catch {
    return null;
  }
}

function normalizeReferences(refs) {
  if (!Array.isArray(refs)) return [];
  const clean = refs.map(normalizeUrl).filter(Boolean);
  const seen = new Set();
  const out = [];
  for (const url of clean) {
    if (!seen.has(url)) {
      seen.add(url);
      out.push(url);
    }
  }
  return out;
}

router.post('/cves/normalize', requireAuth, requireRole(ROLES.ADMIN), async (req, res) => {
  const limit = Number.isInteger(req.body?.limit) ? Math.max(0, req.body.limit) : 0;
  const dryRun = Boolean(req.body?.dryRun);

  const sql = `SELECT id, metadata FROM resources WHERE type = 'cve' ${limit ? 'LIMIT ?' : ''}`;
  const params = limit ? [limit] : [];

  db.all(sql, params, async (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    let updated = 0;
    let unchanged = 0;
    const failures = [];

    const updateRow = (id, meta) =>
      new Promise((resolve) => {
        db.run(`UPDATE resources SET metadata = ? WHERE id = ?`, [JSON.stringify(meta), id], function (updErr) {
          if (updErr) return resolve({ ok: false, id, error: String(updErr.message || updErr) });
          return resolve({ ok: true });
        });
      });

    for (const r of rows || []) {
      let meta;
      try {
        meta = JSON.parse(r.metadata);
      } catch {
        failures.push({ id: r.id, error: 'Invalid JSON metadata' });
        continue;
      }

      const prevRefs = Array.isArray(meta.references) ? meta.references : [];
      const nextRefs = normalizeReferences(prevRefs);

      // Détecter les wrappers même si JSON.stringify paraît identique
      const hasWrappers = prevRefs.some((v) => /^[\s`"'<>]+|[\s`"'<>]+$/.test(String(v)));
      const changed = hasWrappers || JSON.stringify(prevRefs) !== JSON.stringify(nextRefs);

      if (!changed) {
        unchanged += 1;
        continue;
      }

      meta.references = nextRefs;

      if (dryRun) {
        updated += 1;
        continue;
      }

      const result = await updateRow(r.id, meta);
      if (result.ok) {
        updated += 1;
      } else {
        failures.push({ id: r.id, error: result.error });
      }
    }

    return res.json({
      scanned: rows.length,
      updated,
      unchanged,
      failures_count: failures.length,
      dryRun,
      limit: limit || null,
      failures
    });
  });
});

// Liste CVE: assainir les références à l’affichage pour éviter les backticks/guillemets
router.get('/cves', requireAuth, (req, res) => {
  const { cve_id, severity, q } = req.query;
  const page = Math.max(parseInt(req.query.page || '1', 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 100);
  const offset = (page - 1) * limit;

  const where = ['r.type = ?'];
  const params = ['cve'];

  if (cve_id) {
    where.push('UPPER(r.name) = ?');
    params.push(String(cve_id).toUpperCase());
  }
  if (q) {
    where.push('LOWER(r.metadata) LIKE ?');
    params.push(`%${String(q).toLowerCase()}%`);
  }

  const whereSql = `WHERE ${where.join(' AND ')}`;

  const baseAdminSelect = `
    SELECT r.id, r.name, r.metadata, r.owner_id, u.username AS owner_username
    FROM resources r
    LEFT JOIN users u ON r.owner_id = u.id
    ${whereSql}
    ORDER BY r.id DESC
    LIMIT ? OFFSET ?
  `;
  const baseUserSelect = `
    SELECT r.id, r.name, r.metadata, r.owner_id
    FROM resources r
    ${whereSql}
    ORDER BY r.id DESC
    LIMIT ? OFFSET ?
  `;

  const sql = req.user.role === ROLES.ADMIN ? baseAdminSelect : baseUserSelect;
  const finalParams = params.concat([limit, offset]);

  db.all(sql, finalParams, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    let items = (rows || []).map(r => {
      const meta = (() => { try { return JSON.parse(r.metadata); } catch { return {}; } })();

      // sanitize references pour la sortie
      const refs = normalizeReferences(Array.isArray(meta.references) ? meta.references : []);

      return {
        id: r.id,
        owner_id: r.owner_id,
        owner_username: r.owner_username,
        cve_id: meta.cve_id,
        title: meta.title,
        description: meta.description,
        description_html: meta.description_html,
        severity: meta.severity,
        cvss_score: meta.cvss_score,
        affected_products: meta.affected_products,
        references: refs,
        recommendation: meta.recommendation,
        published_at: meta.published_at,
        last_modified: meta.last_modified
      };
    });

    if (severity) {
      const sev = String(severity).toLowerCase();
      items = items.filter(it => String(it.severity || '').toLowerCase() === sev);
    }

    // Calcule total_count avec le même WHERE, sans LIMIT/OFFSET
    const countSql = `
      SELECT COUNT(*) AS total
      FROM resources r
      ${req.user.role === ROLES.ADMIN ? 'LEFT JOIN users u ON r.owner_id = u.id' : ''}
      ${whereSql}
    `;
    db.get(countSql, params, (cntErr, cntRow) => {
      if (cntErr) return res.status(500).json({ error: 'DB error' });
      const total_count = Number(cntRow?.total || 0);
      const has_next = offset + items.length < total_count;
      return res.json({ page, limit, count: items.length, total_count, has_next, items });
    });
  });
});

// Normalisation "force" (admin): applique la sanitisation et écrit en DB pour tous les CVE
// Body: { limit?: number } (optionnel)
router.post('/cves/normalize-force', requireAuth, requireRole(ROLES.ADMIN), async (req, res) => {
  const limit = Number.isInteger(req.body?.limit) ? Math.max(0, req.body.limit) : 0;
  const sql = `SELECT id, metadata FROM resources WHERE type = 'cve' ${limit ? 'LIMIT ?' : ''}`;
  const params = limit ? [limit] : [];

  db.all(sql, params, async (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    let updated = 0;
    const failures = [];

    const updateRow = (id, meta) =>
      new Promise((resolve) => {
        db.run(`UPDATE resources SET metadata = ? WHERE id = ?`, [JSON.stringify(meta), id], function (updErr) {
          if (updErr) return resolve({ ok: false, id, error: String(updErr.message || updErr) });
          return resolve({ ok: true });
        });
      });

    for (const r of rows || []) {
      let meta;
      try {
        meta = JSON.parse(r.metadata);
      } catch {
        failures.push({ id: r.id, error: 'Invalid JSON metadata' });
        continue;
      }

      const prevRefs = Array.isArray(meta.references) ? meta.references : [];
      const nextRefs = normalizeReferences(prevRefs);

      // Écrit toujours si l’array existe (force), mais compte comme update seulement si diffère
      const changed = JSON.stringify(prevRefs) !== JSON.stringify(nextRefs);

      meta.references = nextRefs;

      const result = await updateRow(r.id, meta);
      if (!result.ok) {
        failures.push({ id: r.id, error: result.error });
      } else if (changed) {
        updated += 1;
      }
    }

    return res.json({
      scanned: rows.length,
      updated,
      failures_count: failures.length,
      limit: limit || null,
      failures
    });
  });
});

module.exports = router;