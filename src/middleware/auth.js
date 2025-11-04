const jwt = require('jsonwebtoken');
const { ROLES } = require('../utils/roles');

const DISABLE_AUTH = String(process.env.DISABLE_AUTH || '').toLowerCase() === 'true';

const requireAuth = (req, res, next) => {
  if (DISABLE_AUTH) {
    // Bypass auth: set a default admin-like user for downstream routes
    req.user = { id: 0, role: ROLES.ADMIN, username: 'guest' };
    return next();
  }
  const auth = req.headers.authorization || '';
  const [scheme, token] = auth.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: payload.sub, role: payload.role, username: payload.username };
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const requireRole = (role) => (req, res, next) => {
  if (DISABLE_AUTH) return next();
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  if (req.user.role !== role) return res.status(403).json({ error: 'Forbidden: insufficient role' });
  return next();
};

module.exports = { requireAuth, requireRole, ROLES };