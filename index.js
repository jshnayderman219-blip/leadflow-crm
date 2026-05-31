const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, query, param, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ── Security Middleware ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://leadflow-crm-pmof.onrender.com,http://localhost:3000').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

app.use(express.json({ limit: '1mb' }));
app.disable('x-powered-by');

// ── Rate Limiting ──
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many requests. Try again later.' } } });

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// ── Config ──
const JWT_SECRET = process.env.JWT_SECRET || 'leadflow-dev-secret-change-in-production';
const JWT_EXPIRY = '24h';
const API_BASE = process.env.API_BASE_URL || 'https://alivion-lead-flow.onrender.com';

// ── In-Memory User Store (for demo/MVP; replace with DB in production) ──
const users = new Map();
// Add default demo user
(async () => {
  const demoHash = await bcrypt.hash('demo123', 10);
  users.set('demo@leadflow.ai', {
    id: 1, email: 'demo@leadflow.ai', full_name: 'Alex Morgan',
    password: demoHash, role: 'agent', plan: 'professional',
    created_at: new Date().toISOString()
  });
  const adminHash = await bcrypt.hash('admin123', 10);
  users.set('admin@leadflow.ai', {
    id: 2, email: 'admin@leadflow.ai', full_name: 'Admin User',
    password: adminHash, role: 'admin', plan: 'enterprise',
    created_at: new Date().toISOString()
  });
})();

// ── Auth Middleware ──
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required' } });
  }
  try {
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = users.get(decoded.email);
    if (!user) throw new Error('User not found');
    req.user = { id: user.id, email: user.email, full_name: user.full_name, role: user.role, plan: user.plan };
    next();
  } catch (e) {
    return res.status(401).json({ success: false, error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' } });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required' } });
    if (!roles.includes(req.user.role)) return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Insufficient permissions' } });
    next();
  };
}

// ── Input Sanitization ──
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>]/g, '').trim();
}
function sanitizeAll(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const cleaned = {};
  for (const [k, v] of Object.entries(obj)) {
    cleaned[k] = typeof v === 'string' ? sanitize(v) : v;
  }
  return cleaned;
}
app.use('/api/', (req, res, next) => {
  if (req.body && typeof req.body === 'object') req.body = sanitizeAll(req.body);
  next();
});

// ── Validation ──
function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      error: { code: 'VALIDATION_ERROR', message: 'Invalid input', details: errors.array() }
    });
  }
  next();
}

// ── Proxy Helper ──
async function proxyToAPI(method, apiPath, req, res, bodyTransform) {
  try {
    const headers = { 'Content-Type': 'application/json' };
    const options = { method, headers };
    if (bodyTransform && req.body) {
      options.body = JSON.stringify(bodyTransform(req.body));
    } else if (req.body && Object.keys(req.body).length > 0) {
      options.body = JSON.stringify(req.body);
    }
    const r = await fetch(`${API_BASE}${apiPath}`, options);
    const data = await r.json().catch(() => ({}));
    
    if (!r.ok) {
      return res.status(r.status).json({
        success: false,
        error: { code: 'UPSTREAM_ERROR', message: data.error || data.message || 'Upstream error', upstream: data }
      });
    }
    
    // Transform response for CRM compatibility
    if (method === 'GET' && apiPath === '/api/leads') {
      const leads = (data.leads || data).map(l => ({
        id: l.id, name: l.name || '', email: l.email || '', phone: l.phone || '',
        lead_source: l.source || l.lead_source || 'Website', message: l.message || '',
        property_interest: l.property_interest || '', preferred_location: l.preferred_location || '',
        budget_min: l.budget_min, budget_max: l.budget_max, timeline: l.timeline || '',
        stage: l.stage || 'new_lead', ai_score: l.ai_score || 50, notes: l.notes || '',
        last_contacted: l.last_contacted || '', created_at: l.created_at, updated_at: l.updated_at
      }));
      return res.json(leads);
    }
    
    res.json(data);
  } catch (e) {
    console.error(`Proxy error [${method} ${apiPath}]:`, e.message);
    res.status(502).json({
      success: false,
      error: { code: 'PROXY_ERROR', message: 'Backend service unavailable' }
    });
  }
}

// ── AUTH ROUTES ──
app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('full_name').isString().trim().isLength({ min: 1 }),
], handleValidation, async (req, res) => {
  const { email, password, full_name } = req.body;
  if (users.has(email)) {
    return res.status(409).json({ success: false, error: { code: 'EMAIL_EXISTS', message: 'Email already registered' } });
  }
  const hash = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), email, full_name, password: hash, role: 'agent', plan: 'starter', created_at: new Date().toISOString() };
  users.set(email, user);
  const token = jwt.sign({ id: user.id, email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
  res.status(201).json({ success: true, token, user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role, plan: user.plan } });
});

app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isString().isLength({ min: 1 }),
], handleValidation, async (req, res) => {
  const { email, password } = req.body;
  const user = users.get(email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ success: false, error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' } });
  }
  const token = jwt.sign({ id: user.id, email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
  res.json({ success: true, token, user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role, plan: user.plan } });
});

app.post('/api/auth/reset-password', [body('email').isEmail().normalizeEmail()], handleValidation, (req, res) => {
  // Placeholder: In production, send email with reset token
  res.json({ success: true, message: 'If the email exists, a reset link has been sent.' });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ success: true, user: req.user });
});

// ── LEADS ROUTES ──
app.get('/api/leads', authenticate, (req, res) => proxyToAPI('GET', '/api/leads', req, res));
app.get('/api/leads/:id', authenticate, [param('id').isInt()], handleValidation, (req, res) => proxyToAPI('GET', `/api/leads/${req.params.id}`, req, res));

app.post('/api/leads', authenticate, [
  body('name').optional().isString().trim(),
  body('email').optional().isEmail().normalizeEmail(),
  body('phone').optional().isString().trim(),
], handleValidation, (req, res) => {
  proxyToAPI('POST', '/api/leads', req, res, (body) => ({
    name: body.name || '', email: body.email || '', phone: body.phone || '',
    message: body.message || '', source: body.lead_source || 'Website'
  }));
});

app.put('/api/leads/:id', authenticate, [param('id').isInt()], handleValidation, (req, res) => proxyToAPI('PUT', `/api/leads/${req.params.id}`, req, res));
app.delete('/api/leads/:id', authenticate, [param('id').isInt()], handleValidation, (req, res) => proxyToAPI('DELETE', `/api/leads/${req.params.id}`, req, res));
app.put('/api/leads/:id/stage', authenticate, [param('id').isInt(), body('stage').isString()], handleValidation, (req, res) => proxyToAPI('PUT', `/api/leads/${req.params.id}/stage`, req, res));
app.post('/api/leads/:id/score', authenticate, [param('id').isInt()], handleValidation, (req, res) => proxyToAPI('POST', `/api/leads/${req.params.id}/score`, req, res));
app.post('/api/leads/:id/communications', authenticate, [param('id').isInt(), body('content').isString().isLength({ min: 1 })], handleValidation, (req, res) => proxyToAPI('POST', `/api/leads/${req.params.id}/communications`, req, res));

// ── APPOINTMENTS ──
app.get('/api/appointments', authenticate, (req, res) => proxyToAPI('GET', '/api/appointments', req, res));
app.post('/api/appointments', authenticate, [
  body('lead_id').isInt(),
  body('title').optional().isString(),
  body('appt_type').optional().isString(),
  body('start_time').isString(),
  body('end_time').optional().isString(),
], handleValidation, (req, res) => proxyToAPI('POST', '/api/appointments', req, res));
app.put('/api/appointments/:id', authenticate, [param('id').isInt(), body('status').isString()], handleValidation, (req, res) => proxyToAPI('PUT', `/api/appointments/${req.params.id}`, req, res));

// ── CAMPAIGNS ──
app.get('/api/campaigns', authenticate, (req, res) => proxyToAPI('GET', '/api/campaigns', req, res));
app.post('/api/campaigns', authenticate, [body('name').isString().isLength({ min: 1 })], handleValidation, (req, res) => proxyToAPI('POST', '/api/campaigns', req, res));
app.put('/api/campaigns/:id', authenticate, [param('id').isInt()], handleValidation, (req, res) => proxyToAPI('PUT', `/api/campaigns/${req.params.id}`, req, res));

// ── ANALYTICS ──
app.get('/api/analytics/dashboard', authenticate, (req, res) => proxyToAPI('GET', '/api/analytics/dashboard', req, res));
app.get('/api/analytics/performance', authenticate, (req, res) => proxyToAPI('GET', '/api/analytics/performance', req, res));

// ── AI GENERATE ──
const AI_PROVIDER = process.env.AI_PROVIDER || 'openai'; // openai, claude, or 'mock'
const AI_API_KEY = process.env.AI_API_KEY || '';
const AI_MODEL = process.env.AI_MODEL || 'gpt-4o-mini';

app.post('/api/ai/generate', authenticate, [
  body('type').isString(),
  body('tone').optional().isString(),
  body('lead_context').optional().isObject(),
], handleValidation, async (req, res) => {
  const { type, tone, lead_context } = req.body;
  const name = lead_context?.name || 'there';
  
  // Mock fallback (used when no API key configured)
  const templates = {
    sms_followup: { professional: `Hi ${name}, following up on our conversation about your property search. Let me know if you'd like to schedule a showing this week. - ${req.user.full_name}`, friendly: `Hey ${name}! 👋 Just checking in — any properties catch your eye? Happy to set up a showing whenever you're ready! 😊`, urgent: `Hi ${name}, a property matching your criteria just hit the market. Would you like to see it today? - ${req.user.full_name.split(' ')[0]}`, casual: `Hey ${name}, what's up? Got any questions about the listings I sent over? ✌️` },
    email_followup: { professional: `Dear ${name},\n\nI wanted to follow up regarding your real estate needs. Please let me know if you have any questions or would like to explore additional options.\n\nBest regards,\n${req.user.full_name}`, friendly: `Hi ${name}!\n\nHope you're doing well! 😊 Just wanted to check in and see how your search is going. Let me know if I can help with anything!\n\nCheers,\n${req.user.full_name.split(' ')[0]}` },
    call_script: { professional: `Opening: "Hi ${name}, this is ${req.user.full_name} with LeadFlow Realty. How are you today?"\n\nPurpose: Check in on their property search timeline\n\nKey questions:\n1. Have you viewed any properties recently?\n2. Has your budget or location preference changed?\n3. Would you like to schedule showings this weekend?\n\nClose: Set next contact date` },
  };
  
  // If API key configured, use real AI
  if (AI_API_KEY && AI_API_KEY.length > 10 && AI_PROVIDER !== 'mock') {
    try {
      let content;
      if (AI_PROVIDER === 'openai') {
        const r = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AI_API_KEY}` },
          body: JSON.stringify({
            model: AI_MODEL,
            messages: [
              { role: 'system', content: `You are a real estate agent's AI assistant. Generate a ${tone || 'professional'} ${type.replace(/_/g, ' ')} message. Sign as ${req.user.full_name}. Lead context: ${JSON.stringify(lead_context)}. Keep it concise and professional.` },
              { role: 'user', content: `Generate a ${type.replace(/_/g, ' ')} message for lead ${name}.` }
            ],
            max_tokens: 500,
            temperature: 0.7
          })
        });
        const data = await r.json();
        content = data.choices?.[0]?.message?.content;
      }
      if (content) {
        return res.json({ content, ai_generated: true, type, tone, provider: AI_PROVIDER });
      }
    } catch (e) { console.error('AI generate error:', e.message); }
  }
  
  // Fallback to templates
  const template = (templates[type] || templates.sms_followup)[tone || 'professional'] || Object.values(templates.sms_followup)[0];
  res.json({ content: template, ai_generated: false, type, tone, provider: 'template' });
});

// ── BILLING PLACEHOLDER ──
app.get('/api/billing/plans', (req, res) => {
  res.json({
    success: true,
    plans: [
      { id: 'starter', name: 'Starter', price: 29, interval: 'month', features: ['1 user', '500 leads', 'Basic pipeline', 'Email support'] },
      { id: 'professional', name: 'Professional', price: 79, interval: 'month', features: ['3 users', '2,500 leads', 'AI assistant', 'SMS', 'Integrations'] },
      { id: 'team', name: 'Team', price: 199, interval: 'month', features: ['10 users', '10,000 leads', 'Team analytics', 'Custom pipelines'] },
    ]
  });
});

app.get('/api/billing/subscription', authenticate, (req, res) => {
  res.json({ success: true, subscription: { plan: req.user.plan, status: 'active', next_billing: null } });
});

// ── HEALTH ──
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', mode: 'proxy', upstream: API_BASE, timestamp: new Date().toISOString() });
});

// ── Serve Frontend ──
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── 404 Handler (must be last) ──
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: { code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` }
  });
});

// ── Global Error Handler ──
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body too large' } });
  }
  res.status(500).json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
});

// ── Start ──
app.listen(PORT, () => console.log(`LeadFlow CRM v2 running on port ${PORT} (proxy → ${API_BASE})`));
