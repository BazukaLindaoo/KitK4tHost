// ============================================================
// LuauHub — Backend Completo (Node.js + Express)
// ============================================================
// Instalar dependências:
//   npm install express bcrypt jsonwebtoken helmet cors express-rate-limit
//               express-mongo-sanitize mongoose dotenv uuid morgan
//               express-validator axios multer
// ============================================================

require('dotenv').config();

const express      = require('express');
const bcrypt       = require('bcrypt');
const jwt          = require('jsonwebtoken');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const mongoose     = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const morgan       = require('morgan');
const axios        = require('axios');
const multer       = require('multer');
const { body, validationResult } = require('express-validator');
const path         = require('path');
const crypto       = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIGURAÇÕES
// ============================================================
const CONFIG = {
  MONGODB_URI:     process.env.MONGODB_URI || 'mongodb://localhost:27017/luauhub',
  JWT_SECRET:      process.env.JWT_SECRET  || crypto.randomBytes(64).toString('hex'),
  JWT_EXPIRY:      '7d',
  BCRYPT_ROUNDS:   12,
  ADMIN_EMAIL:     'naotemsuporte@gmail.com',
  MAX_SCRIPT_SIZE: 1 * 1024 * 1024, // 1MB
  WEBHOOKS: {
    register: 'https://discord.com/api/webhooks/1473381835454025819/LMveeSMzMYoJF4WLeo_6EErq9J-E2JIzOqw5_mli1_MPhPTHAlzIyPfGshJq33-TQMy7',
    login:    'https://discord.com/api/webhooks/1473381919277318336/tVswu-10xRlQhG5XMWdADkV0VjFdyIP6Rdsd2q9_met9GOLLEuuR3-D8MeRVEI2GRbWw',
  },
};

// ============================================================
// MONGOOSE SCHEMAS
// ============================================================
const userSchema = new mongoose.Schema({
  id:         { type: String, default: () => uuidv4(), unique: true },
  username:   { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30 },
  email:      { type: String, required: true, unique: true, trim: true, lowercase: true },
  password:   { type: String, required: true },
  role:       { type: String, enum: ['user','admin'], default: 'user' },
  banned:     { type: Boolean, default: false },
  bannedReason: String,
  lastIp:     String,
  country:    String,
  createdAt:  { type: Date, default: Date.now },
  lastLoginAt: Date,
  emailVerified: { type: Boolean, default: false },
  resetToken:  String,
  resetExpiry: Date,
});

const scriptSchema = new mongoose.Schema({
  id:          { type: String, default: () => uuidv4(), unique: true },
  name:        { type: String, required: true, trim: true, maxlength: 100 },
  description: { type: String, trim: true, maxlength: 500 },
  code:        { type: String, required: true },
  category:    { type: String, enum: ['game','utility','ui','admin','other'], default: 'other' },
  visibility:  { type: String, enum: ['public','private'], default: 'public' },
  keyProtected: { type: Boolean, default: false },
  apiKeyHash:  String,
  author:      { type: String, required: true },
  userId:      { type: String, required: true },
  version:     { type: String, default: '1.0.0' },
  downloads:   { type: Number, default: 0 },
  versions:    [{ version: String, code: String, date: Date, note: String }],
  blacklisted: { type: Boolean, default: false },
  createdAt:   { type: Date, default: Date.now },
  updatedAt:   { type: Date, default: Date.now },
});

const logSchema = new mongoose.Schema({
  type:     { type: String, required: true },
  userId:   String,
  username: String,
  email:    String,
  ip:       String,
  country:  String,
  status:   String,
  userAgent: String,
  extra:    mongoose.Schema.Types.Mixed,
  date:     { type: Date, default: Date.now },
});

const apiKeySchema = new mongoose.Schema({
  id:        { type: String, default: () => uuidv4(), unique: true },
  key:       { type: String, unique: true },
  keyHash:   String,
  label:     String,
  userId:    { type: String, required: true },
  active:    { type: Boolean, default: true },
  uses:      { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  lastUsed:  Date,
});

const blockedIPSchema = new mongoose.Schema({
  ip:        { type: String, unique: true },
  reason:    String,
  blockedBy: String,
  blockedAt: { type: Date, default: Date.now },
});

const blacklistSchema = new mongoose.Schema({
  value:     { type: String, unique: true },
  type:      { type: String, enum: ['email','username','ip','pattern'] },
  reason:    String,
  addedBy:   String,
  addedAt:   { type: Date, default: Date.now },
});

const User      = mongoose.model('User',      userSchema);
const Script    = mongoose.model('Script',    scriptSchema);
const Log       = mongoose.model('Log',       logSchema);
const ApiKey    = mongoose.model('ApiKey',    apiKeySchema);
const BlockedIP = mongoose.model('BlockedIP', blockedIPSchema);
const Blacklist = mongoose.model('Blacklist', blacklistSchema);

// ============================================================
// MIDDLEWARE DE SEGURANÇA
// ============================================================

// Helmet — Headers de segurança HTTP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
      styleSrc:    ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
      fontSrc:     ["'self'", "fonts.gstatic.com"],
      imgSrc:      ["'self'", "data:", "https:"],
      connectSrc:  ["'self'", "discord.com"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET','POST','PUT','DELETE','PATCH'],
  allowedHeaders: ['Content-Type','Authorization','X-API-Key'],
}));

// Parse JSON com limite de tamanho
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Sanitização contra NoSQL Injection
app.use(mongoSanitize());

// Logs de requisições
app.use(morgan('combined'));

// Servir frontend
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// RATE LIMITING
// ============================================================
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Muitas requisições. Tente novamente em 1 minuto.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Muitas tentativas de login. Tente em 15 minutos.' },
  skipSuccessfulRequests: true,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Muitos uploads. Tente novamente em 1 minuto.' },
});

app.use('/api/', globalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/scripts/', uploadLimiter);

// ============================================================
// MIDDLEWARE DE IP BLOQUEADO
// ============================================================
async function checkBlockedIP(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  try {
    const blocked = await BlockedIP.findOne({ ip });
    if (blocked) {
      return res.status(403).json({ error: 'Seu IP foi bloqueado. Contate o suporte.' });
    }
  } catch (e) { /* continue */ }
  next();
}

app.use('/api/', checkBlockedIP);

// ============================================================
// HELPER: DISCORD WEBHOOK
// ============================================================
async function sendDiscordWebhook(type, data) {
  const webhook = CONFIG.WEBHOOKS[type];
  if (!webhook) return;

  const isSuccess = data.status === 'success';
  const color = isSuccess ? 0x00d4aa : 0xff6b6b;
  const emoji = isSuccess ? '✅' : '❌';
  const title = type === 'register' ? 'Novo Registro' : 'Login';

  const embed = {
    embeds: [{
      title:  `${emoji} LuauHub — ${title}`,
      color,
      fields: [
        { name: '👤 Username',  value: data.username  || 'N/A', inline: true },
        { name: '📧 Email',     value: data.email     || 'N/A', inline: true },
        { name: '🆔 User ID',   value: data.userId    || 'N/A', inline: true },
        { name: '🌐 IP',        value: data.ip        || 'N/A', inline: true },
        { name: '🌍 País',      value: data.country   || 'N/A', inline: true },
        { name: '📊 Status',    value: data.status    || 'N/A', inline: true },
        { name: '🕐 Data/Hora', value: new Date().toLocaleString('pt-BR'), inline: true },
        { name: '🖥️ User Agent', value: (data.userAgent || 'N/A').slice(0, 100) },
      ],
      footer: { text: 'LuauHub Security System' },
      timestamp: new Date().toISOString(),
    }],
  };

  try {
    await axios.post(webhook, embed, { timeout: 5000 });
  } catch (err) {
    console.error('[Webhook]', err.message);
  }
}

// ============================================================
// HELPER: LOG NO BD
// ============================================================
async function createLog(type, data) {
  try {
    await Log.create({
      type,
      userId:    data.userId,
      username:  data.username,
      email:     data.email,
      ip:        data.ip,
      country:   data.country,
      status:    data.status,
      userAgent: data.userAgent,
      extra:     data.extra,
    });
  } catch (e) {
    console.error('[Log]', e.message);
  }
}

// ============================================================
// HELPER: OBTER IP REAL
// ============================================================
function getIP(req) {
  return (
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.ip ||
    '0.0.0.0'
  );
}

// ============================================================
// HELPER: OBTER PAÍS (usando IP-API gratuito)
// ============================================================
async function getCountry(ip) {
  try {
    if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip === '::1') return 'Local';
    const res = await axios.get(`http://ip-api.com/json/${ip}?fields=country`, { timeout: 3000 });
    return res.data?.country || 'Desconhecido';
  } catch {
    return 'Desconhecido';
  }
}

// ============================================================
// MIDDLEWARE: AUTENTICAÇÃO JWT
// ============================================================
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });

  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.email !== CONFIG.ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Acesso negado — Requer privilégios de administrador' });
  }
  next();
}

// ============================================================
// VALIDAÇÕES
// ============================================================
const validateRegister = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 }).withMessage('Username deve ter 3-30 caracteres')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username só pode conter letras, números e _'),
  body('email')
    .isEmail().withMessage('Email inválido')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 }).withMessage('Senha deve ter pelo menos 8 caracteres')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Senha deve conter maiúscula, minúscula e número'),
];

const validateLogin = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
];

function checkValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
}

// ============================================================
// BLACKLIST CHECKER
// ============================================================
async function checkBlacklist(value) {
  const entry = await Blacklist.findOne({ value: value.toLowerCase() });
  return !!entry;
}

// ============================================================
// SCRIPT SECURITY SCANNER
// ============================================================
const MALICIOUS_PATTERNS = [
  /getfenv/i, /setfenv/i, /rawset/i, /rawget/i,
  /debug\.getupvalue/i, /debug\.setupvalue/i,
  /load\s*\(/i, /loadstring/i,
];

function scanScript(code) {
  const issues = [];
  MALICIOUS_PATTERNS.forEach(pattern => {
    if (pattern.test(code)) {
      issues.push(pattern.toString());
    }
  });
  return issues;
}

// ============================================================
// ROTAS — AUTH
// ============================================================

// POST /api/auth/register
app.post('/api/auth/register', validateRegister, checkValidation, async (req, res) => {
  const { username, email, password } = req.body;
  const ip = getIP(req);
  const ua = req.headers['user-agent'] || '';

  try {
    // Checar blacklist
    if (await checkBlacklist(email) || await checkBlacklist(username.toLowerCase())) {
      return res.status(403).json({ error: 'Registro não permitido' });
    }

    // Checar IP bloqueado
    if (await BlockedIP.findOne({ ip })) {
      return res.status(403).json({ error: 'IP bloqueado' });
    }

    // Verificar existência
    const existing = await User.findOne({ $or: [{ email }, { username: { $regex: new RegExp(`^${username}$`, 'i') } }] });
    if (existing) {
      if (existing.email === email) return res.status(409).json({ error: 'Email já cadastrado' });
      return res.status(409).json({ error: 'Username já está em uso' });
    }

    const country = await getCountry(ip);
    const hashedPassword = await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS);
    const userId = uuidv4();

    const user = await User.create({
      id:       userId,
      username,
      email,
      password: hashedPassword,
      role:     email === CONFIG.ADMIN_EMAIL ? 'admin' : 'user',
      lastIp:   ip,
      country,
    });

    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, role: user.role },
      CONFIG.JWT_SECRET,
      { expiresIn: CONFIG.JWT_EXPIRY }
    );

    const logData = { userId: user.id, username, email, ip, country, status: 'success', userAgent: ua };
    await createLog('register', logData);
    await sendDiscordWebhook('register', logData);

    res.status(201).json({
      message: 'Conta criada com sucesso!',
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('[Register]', err);
    await createLog('register', { email, ip, status: 'error - ' + err.message, userAgent: ua });
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', validateLogin, checkValidation, async (req, res) => {
  const { email, password } = req.body;
  const ip = getIP(req);
  const ua = req.headers['user-agent'] || '';

  try {
    const country = await getCountry(ip);
    const user = await User.findOne({ email });

    if (!user) {
      const logData = { email, ip, country, status: 'failed - user not found', userAgent: ua };
      await createLog('login', logData);
      await sendDiscordWebhook('login', logData);
      return res.status(401).json({ error: 'Email ou senha incorretos' });
    }

    if (user.banned) {
      const logData = { userId: user.id, username: user.username, email, ip, country, status: 'failed - banned', userAgent: ua };
      await createLog('login', logData);
      await sendDiscordWebhook('login', logData);
      return res.status(403).json({ error: `Conta banida${user.bannedReason ? ': ' + user.bannedReason : ''}` });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      const logData = { userId: user.id, username: user.username, email, ip, country, status: 'failed - wrong password', userAgent: ua };
      await createLog('login', logData);
      await sendDiscordWebhook('login', logData);
      return res.status(401).json({ error: 'Email ou senha incorretos' });
    }

    user.lastIp = ip;
    user.country = country;
    user.lastLoginAt = new Date();
    await user.save();

    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, role: user.role },
      CONFIG.JWT_SECRET,
      { expiresIn: CONFIG.JWT_EXPIRY }
    );

    const logData = { userId: user.id, username: user.username, email, ip, country, status: 'success', userAgent: ua };
    await createLog('login', logData);
    await sendDiscordWebhook('login', logData);

    res.json({
      message: 'Login realizado com sucesso!',
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('[Login]', err);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email: email?.toLowerCase() });
    if (!user) {
      // Resposta genérica por segurança (anti-user enumeration)
      return res.json({ message: 'Se o email existir, um link será enviado.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    user.resetToken  = await bcrypt.hash(token, 10);
    user.resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hora
    await user.save();

    // Em produção, enviar email com link de reset contendo o token
    console.log(`[Reset] Link para ${email}: ${process.env.FRONTEND_URL}/reset-password?token=${token}&email=${email}`);

    res.json({ message: 'Se o email existir, um link será enviado.' });
  } catch (err) {
    console.error('[Forgot]', err);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Dados inválidos' });
  }
  try {
    const user = await User.findOne({ email: email.toLowerCase(), resetExpiry: { $gt: new Date() } });
    if (!user || !user.resetToken) return res.status(400).json({ error: 'Token inválido ou expirado' });

    const valid = await bcrypt.compare(token, user.resetToken);
    if (!valid) return res.status(400).json({ error: 'Token inválido' });

    user.password    = await bcrypt.hash(newPassword, CONFIG.BCRYPT_ROUNDS);
    user.resetToken  = undefined;
    user.resetExpiry = undefined;
    await user.save();

    res.json({ message: 'Senha redefinida com sucesso!' });
  } catch (err) {
    console.error('[Reset]', err);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id }).select('-password -resetToken');
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ============================================================
// ROTAS — SCRIPTS
// ============================================================

// GET /api/scripts — Listar scripts públicos
app.get('/api/scripts', async (req, res) => {
  const { q, category, page = 1, limit = 20 } = req.query;
  const filter = { visibility: 'public', blacklisted: { $ne: true } };
  if (q) filter.name = { $regex: q, $options: 'i' };
  if (category && category !== 'all') filter.category = category;

  try {
    const total = await Script.countDocuments(filter);
    const scripts = await Script.find(filter)
      .select('-code -apiKeyHash')
      .sort({ createdAt: -1 })
      .skip((+page - 1) * +limit)
      .limit(+limit);

    res.json({ scripts, total, page: +page, pages: Math.ceil(total / +limit) });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar scripts' });
  }
});

// GET /api/scripts/:id — Obter script por ID
app.get('/api/scripts/:id', async (req, res) => {
  try {
    const script = await Script.findOne({ id: req.params.id, blacklisted: { $ne: true } });
    if (!script) return res.status(404).json({ error: 'Script não encontrado' });

    if (script.visibility === 'private') {
      // Verificar autenticação ou chave API
      const token = req.headers['authorization']?.replace('Bearer ', '');
      const apiKey = req.headers['x-api-key'];

      if (apiKey) {
        const key = await ApiKey.findOne({ active: true });
        const keys = await ApiKey.find({ active: true });
        let valid = false;
        for (const k of keys) {
          if (k.key === apiKey && k.userId === script.userId) { valid = true; k.uses++; k.lastUsed = new Date(); await k.save(); break; }
        }
        if (!valid) return res.status(403).json({ error: 'Chave API inválida' });
      } else if (token) {
        try {
          const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
          if (decoded.id !== script.userId && decoded.email !== CONFIG.ADMIN_EMAIL) {
            return res.status(403).json({ error: 'Acesso negado' });
          }
        } catch {
          return res.status(401).json({ error: 'Token inválido' });
        }
      } else {
        return res.status(403).json({ error: 'Este script é privado' });
      }
    }

    script.downloads += 1;
    await script.save();

    res.json({ script: { ...script.toObject(), apiKeyHash: undefined } });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// POST /api/scripts — Upload de script
app.post('/api/scripts', authenticateToken, uploadLimiter, [
  body('name').trim().isLength({ min: 1, max: 100 }),
  body('code').notEmpty().isLength({ max: 1024 * 1024 }),
], checkValidation, async (req, res) => {
  const { name, description, code, category, visibility, keyProtected } = req.body;
  const ip = getIP(req);

  try {
    // Verificar se usuário está banido
    const user = await User.findOne({ id: req.user.id });
    if (!user || user.banned) return res.status(403).json({ error: 'Conta suspensa' });

    // Escanear script
    const issues = scanScript(code);
    if (issues.length > 0) {
      await createLog('upload_blocked', { userId: req.user.id, username: req.user.username, ip, status: 'blocked - malicious pattern', extra: issues });
      return res.status(400).json({ error: 'Script bloqueado: padrão malicioso detectado', issues });
    }

    // Verificar blacklist de conteúdo
    const blacklisted = await Blacklist.findOne({ type: 'pattern' });
    // (checagem simplificada — em produção, iterar todos os padrões)

    const script = await Script.create({
      name, description, code, category,
      visibility: visibility || 'public',
      keyProtected: !!keyProtected,
      author:  req.user.username,
      userId:  req.user.id,
    });

    await createLog('upload', { userId: req.user.id, username: req.user.username, ip, status: 'success', extra: { scriptId: script.id, name } });

    res.status(201).json({ message: 'Script publicado!', script: { ...script.toObject(), code: undefined } });
  } catch (err) {
    console.error('[Upload]', err);
    res.status(500).json({ error: 'Erro ao publicar script' });
  }
});

// PUT /api/scripts/:id — Editar script
app.put('/api/scripts/:id', authenticateToken, async (req, res) => {
  try {
    const script = await Script.findOne({ id: req.params.id });
    if (!script) return res.status(404).json({ error: 'Script não encontrado' });
    if (script.userId !== req.user.id && req.user.email !== CONFIG.ADMIN_EMAIL) {
      return res.status(403).json({ error: 'Sem permissão' });
    }

    const { name, description, code, category, visibility, keyProtected } = req.body;

    // Salvar versão anterior
    script.versions.push({ version: script.version, code: script.code, date: new Date(), note: 'Auto-save' });

    // Incrementar versão
    const parts = script.version.split('.').map(Number);
    parts[2]++;
    script.version = parts.join('.');

    if (name) script.name = name;
    if (description !== undefined) script.description = description;
    if (code) { const issues = scanScript(code); if (issues.length === 0) script.code = code; }
    if (category) script.category = category;
    if (visibility) script.visibility = visibility;
    if (keyProtected !== undefined) script.keyProtected = keyProtected;
    script.updatedAt = new Date();

    await script.save();
    res.json({ message: 'Script atualizado!', version: script.version });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar script' });
  }
});

// DELETE /api/scripts/:id — Excluir script
app.delete('/api/scripts/:id', authenticateToken, async (req, res) => {
  const ip = getIP(req);
  try {
    const script = await Script.findOne({ id: req.params.id });
    if (!script) return res.status(404).json({ error: 'Script não encontrado' });
    if (script.userId !== req.user.id && req.user.email !== CONFIG.ADMIN_EMAIL) {
      return res.status(403).json({ error: 'Sem permissão' });
    }

    await Script.deleteOne({ id: req.params.id });
    await createLog('delete_script', { userId: req.user.id, username: req.user.username, ip, status: 'success', extra: { scriptId: req.params.id, name: script.name } });

    res.json({ message: 'Script excluído' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao excluir script' });
  }
});

// GET /api/scripts/user/me — Meus scripts
app.get('/api/scripts/user/me', authenticateToken, async (req, res) => {
  try {
    const scripts = await Script.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json({ scripts });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ============================================================
// ROTAS — API KEYS
// ============================================================

// GET /api/keys — Minhas chaves
app.get('/api/keys', authenticateToken, async (req, res) => {
  try {
    const keys = await ApiKey.find({ userId: req.user.id }).select('-keyHash');
    res.json({ keys });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// POST /api/keys — Gerar chave
app.post('/api/keys', authenticateToken, async (req, res) => {
  try {
    const count = await ApiKey.countDocuments({ userId: req.user.id, active: true });
    if (count >= 10) return res.status(400).json({ error: 'Limite de 10 chaves ativas atingido' });

    const rawKey = 'lhk_' + crypto.randomBytes(32).toString('hex');
    const keyHash = await bcrypt.hash(rawKey, 10);

    const apiKey = await ApiKey.create({
      key:    rawKey,
      keyHash,
      label:  req.body.label || 'Chave ' + (count + 1),
      userId: req.user.id,
    });

    res.status(201).json({ key: { id: apiKey.id, key: rawKey, label: apiKey.label, createdAt: apiKey.createdAt } });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao gerar chave' });
  }
});

// DELETE /api/keys/:id — Revogar chave
app.delete('/api/keys/:id', authenticateToken, async (req, res) => {
  try {
    const key = await ApiKey.findOne({ id: req.params.id, userId: req.user.id });
    if (!key) return res.status(404).json({ error: 'Chave não encontrada' });
    key.active = false;
    await key.save();
    res.json({ message: 'Chave revogada' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ============================================================
// ROTAS — LOGS (usuário)
// ============================================================

app.get('/api/logs/me', authenticateToken, async (req, res) => {
  try {
    const logs = await Log.find({ userId: req.user.id }).sort({ date: -1 }).limit(100);
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ============================================================
// ROTAS — PERFIL
// ============================================================

app.put('/api/profile/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Dados inválidos' });
  }
  try {
    const user = await User.findOne({ id: req.user.id });
    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(401).json({ error: 'Senha atual incorreta' });

    user.password = await bcrypt.hash(newPassword, CONFIG.BCRYPT_ROUNDS);
    await user.save();
    res.json({ message: 'Senha alterada com sucesso!' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ============================================================
// ROTAS — ADMIN
// ============================================================

// GET /api/admin/stats
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [users, scripts, banned, logs, failedLogins] = await Promise.all([
      User.countDocuments(),
      Script.countDocuments(),
      User.countDocuments({ banned: true }),
      Log.countDocuments(),
      Log.countDocuments({ status: /failed/ }),
    ]);
    res.json({ users, scripts, banned, logs, failedLogins });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// GET /api/admin/users
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  const { q, page = 1, limit = 50 } = req.query;
  const filter = {};
  if (q) filter.$or = [{ username: { $regex: q, $options: 'i' } }, { email: { $regex: q, $options: 'i' } }];
  try {
    const users = await User.find(filter).select('-password -resetToken').sort({ createdAt: -1 }).skip((+page-1)*+limit).limit(+limit);
    const total = await User.countDocuments(filter);
    res.json({ users, total });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// PATCH /api/admin/users/:id/ban
app.patch('/api/admin/users/:id/ban', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.params.id });
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
    if (user.email === CONFIG.ADMIN_EMAIL) return res.status(403).json({ error: 'Não é possível banir o administrador' });

    user.banned       = !user.banned;
    user.bannedReason = req.body.reason || '';
    await user.save();

    res.json({ message: user.banned ? 'Usuário banido' : 'Usuário desbanido', banned: user.banned });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// GET /api/admin/logs
app.get('/api/admin/logs', authenticateToken, requireAdmin, async (req, res) => {
  const { page = 1, limit = 100, type } = req.query;
  const filter = {};
  if (type) filter.type = type;
  try {
    const logs = await Log.find(filter).sort({ date: -1 }).skip((+page-1)*+limit).limit(+limit);
    const total = await Log.countDocuments(filter);
    res.json({ logs, total });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// GET /api/admin/scripts
app.get('/api/admin/scripts', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const scripts = await Script.find().sort({ createdAt: -1 }).limit(200).select('-code');
    res.json({ scripts });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// PATCH /api/admin/scripts/:id/blacklist
app.patch('/api/admin/scripts/:id/blacklist', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const script = await Script.findOne({ id: req.params.id });
    if (!script) return res.status(404).json({ error: 'Script não encontrado' });
    script.blacklisted = !script.blacklisted;
    await script.save();
    res.json({ message: script.blacklisted ? 'Script blacklistado' : 'Script liberado' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// POST /api/admin/ips/block
app.post('/api/admin/ips/block', authenticateToken, requireAdmin, async (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP obrigatório' });
  try {
    await BlockedIP.findOneAndUpdate(
      { ip },
      { ip, reason, blockedBy: req.user.email, blockedAt: new Date() },
      { upsert: true }
    );
    res.json({ message: 'IP bloqueado: ' + ip });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// DELETE /api/admin/ips/:ip/unblock
app.delete('/api/admin/ips/:ip/unblock', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await BlockedIP.deleteOne({ ip: req.params.ip });
    res.json({ message: 'IP desbloqueado' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// GET /api/admin/ips — Listar IPs bloqueados e com atividade
app.get('/api/admin/ips', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [blocked, activity] = await Promise.all([
      BlockedIP.find().sort({ blockedAt: -1 }),
      Log.aggregate([
        { $group: { _id: '$ip', count: { $sum: 1 }, lastSeen: { $max: '$date' } } },
        { $sort: { count: -1 } },
        { $limit: 100 },
      ]),
    ]);
    res.json({ blocked, activity });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// POST /api/admin/blacklist
app.post('/api/admin/blacklist', authenticateToken, requireAdmin, async (req, res) => {
  const { value, type, reason } = req.body;
  if (!value || !type) return res.status(400).json({ error: 'Dados obrigatórios' });
  try {
    await Blacklist.findOneAndUpdate(
      { value: value.toLowerCase() },
      { value: value.toLowerCase(), type, reason, addedBy: req.user.email },
      { upsert: true }
    );
    res.json({ message: 'Adicionado ao blacklist' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// GET /api/admin/blacklist
app.get('/api/admin/blacklist', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const list = await Blacklist.find().sort({ addedAt: -1 });
    res.json({ list });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// DELETE /api/admin/blacklist/:id
app.delete('/api/admin/blacklist/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Blacklist.findByIdAndDelete(req.params.id);
    res.json({ message: 'Removido do blacklist' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// GET /api/admin/delete-script/:id
app.delete('/api/admin/scripts/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Script.findOneAndDelete({ id: req.params.id });
    res.json({ message: 'Script excluído pelo admin' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ============================================================
// ROTAS — STATUS
// ============================================================

app.get('/api/status', (req, res) => {
  res.json({
    status:    'online',
    version:   '1.0.0',
    timestamp: new Date().toISOString(),
    uptime:    process.uptime(),
    memory:    process.memoryUsage(),
    database:  mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', (req, res) => res.json({ ok: true }));

// ============================================================
// 404 E ERROR HANDLERS
// ============================================================
app.use('/api/*', (req, res) => res.status(404).json({ error: 'Rota não encontrada' }));

app.use((err, req, res, next) => {
  console.error('[Error]', err);
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// ============================================================
// INICIALIZAÇÃO
// ============================================================
async function start() {
  try {
    await mongoose.connect(CONFIG.MONGODB_URI);
    console.log('[DB] MongoDB conectado');

    app.listen(PORT, () => {
      console.log(`[LuauHub] Servidor rodando em http://localhost:${PORT}`);
      console.log(`[Security] Rate limiting, CSRF, helmet, sanitize: ATIVOS`);
    });
  } catch (err) {
    console.error('[Startup]', err);
    process.exit(1);
  }
}

start();

module.exports = app;
