const db = require('../db');

async function logAudit({ actorId, action, entityType, entityId = null, details = null }) {
  return new Promise((resolve) => {
    db.run(
      `INSERT INTO audit_logs (actor_id, action, entity_type, entity_id, details) VALUES (?,?,?,?,?)`,
      [actorId || null, String(action), String(entityType), entityId ? String(entityId) : null, details ? JSON.stringify(details) : null],
      function (err) {
        if (err) return resolve({ ok: false, error: String(err.message || err) });
        return resolve({ ok: true, id: this.lastID });
      }
    );
  });
}

module.exports = { logAudit };