const { body } = require('express-validator');

module.exports = {
  registerSchema: [
    body('username').isString().isLength({ min: 3, max: 32 }).trim(),
    body('email').isEmail().normalizeEmail(),
    body('password').isString().isLength({ min: 8, max: 128 }),
    body('role').optional().isIn(['admin', 'user'])
  ],
  loginSchema: [
    body('username').isString().notEmpty(),
    body('password').isString().notEmpty()
  ],
  createResourceSchema: [
    body('name').isString().isLength({ min: 1, max: 256 }).trim(),
    body('type').optional().isIn(['product', 'file', 'task']),
    body('metadata').optional().isObject()
  ],
  updateResourceSchema: [
    body('name').optional().isString().isLength({ min: 1, max: 256 }).trim(),
    body('type').optional().isIn(['product', 'file', 'task']),
    body('metadata').optional().isObject()
  ],
  // CVE: création
  createCveSchema: [
    body('cve_id')
      .isString()
      .matches(/^CVE-\d{4}-\d{4,7}$/i)
      .withMessage('Format attendu: CVE-YYYY-NNNN')
      .customSanitizer((v) => String(v).toUpperCase()),
    body('title').isString().isLength({ min: 3, max: 256 }).trim(),
    body('description').isString().isLength({ min: 10, max: 5000 }),
    body('severity')
      .isString()
      .isIn(['low', 'medium', 'high', 'critical'])
      .customSanitizer((v) => String(v).toLowerCase()),
    body('cvss_score').optional().isFloat({ min: 0, max: 10 }),
    body('affected_products').optional().isArray(),
    body('affected_products.*').optional().isString().isLength({ min: 1, max: 256 }),
    body('references').optional().isArray(),
    body('references.*')
      .optional()
      .customSanitizer((v) => String(v).trim().replace(/[`"'<>]/g, ''))
      .isURL({ require_protocol: true }),
    body('recommendation').isString().isLength({ min: 5, max: 5000 }),
    body('published_at').optional().isISO8601(),
    body('last_modified').optional().isISO8601()
  ],
  // CVE: mise à jour partielle
  updateCveSchema: [
    body('cve_id').optional().isString().matches(/^CVE-\d{4}-\d{4,7}$/i).customSanitizer((v) => String(v).toUpperCase()),
    body('title').optional().isString().isLength({ min: 3, max: 256 }).trim(),
    body('description').optional().isString().isLength({ min: 10, max: 5000 }),
    body('severity').optional().isString().isIn(['low', 'medium', 'high', 'critical']).customSanitizer((v) => String(v).toLowerCase()),
    body('cvss_score').optional().isFloat({ min: 0, max: 10 }),
    body('affected_products').optional().isArray(),
    body('affected_products.*').optional().isString().isLength({ min: 1, max: 256 }),
    body('references').optional().isArray(),
    body('references.*')
      .optional()
      .customSanitizer((v) => String(v).trim().replace(/[`"'<>]/g, ''))
      .isURL({ require_protocol: true }),
    body('recommendation').optional().isString().isLength({ min: 5, max: 5000 }),
    body('published_at').optional().isISO8601(),
    body('last_modified').optional().isISO8601()
  ],
  importCveSchema: [
    body('cve_id')
      .isString()
      .matches(/^CVE-\d{4}-\d{4,7}$/i)
      .withMessage('Format attendu: CVE-YYYY-NNNN')
      .customSanitizer((v) => String(v).toUpperCase())
  ],
  importBulkCveSchema: [
    body('year').optional().isInt({ min: 1999, max: 2100 }),
    body('pubStartDate').optional().isISO8601(),
    body('pubEndDate').optional().isISO8601(),
    body('resultsPerPage').optional().isInt({ min: 1, max: 2000 }),
    body('delayMs').optional().isInt({ min: 0, max: 10000 })
  ]
};