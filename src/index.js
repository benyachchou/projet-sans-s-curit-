require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const resourceRoutes = require('./routes/resources');

const app = express();
const DISABLE_SECURITY = String(process.env.DISABLE_SECURITY || '').toLowerCase() === 'true';

// Secure HTTP headers (disabled if DISABLE_SECURITY)
if (!DISABLE_SECURITY) {
  app.use(helmet());
}

// Body parser (limits disabled if DISABLE_SECURITY)
if (!DISABLE_SECURITY) {
  app.use(express.json({ limit: process.env.JSON_BODY_LIMIT || '1mb' }));
  app.use(express.urlencoded({ extended: false, limit: process.env.FORM_BODY_LIMIT || '1mb' }));
} else {
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
}

// CORS (disabled if DISABLE_SECURITY)
if (!DISABLE_SECURITY) {
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
      },
      methods: ['GET', 'POST', 'PATCH', 'DELETE'],
      allowedHeaders: ['Authorization', 'Content-Type'],
      maxAge: 600,
    })
  );
} else {
  app.use(cors());
}

// Rate limiters (disabled if DISABLE_SECURITY)
if (!DISABLE_SECURITY) {
  const globalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    max: parseInt(process.env.RATE_LIMIT_MAX || '1000', 10),
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use(globalLimiter);

  const authLimiter = rateLimit({
    windowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '900000', 10),
    max: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '10', 10),
    message: { error: 'Too many attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use('/api/login', authLimiter);
  app.use('/api/register', authLimiter);
}

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Routes
app.use('/api', authRoutes);
app.use('/api', resourceRoutes);

// 404 handler
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  return res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Secure API listening on port ${PORT}`);
});