'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Secrets ─────────────────────────────────────────────────────
// In production: set these as environment variables. Never commit plain secrets.
const JWT_SECRET = process.env.JWT_SECRET || 'relay_user_jwt_2026__CHANGE_IN_PRODUCTION';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'relay_admin_jwt_2026__CHANGE_IN_PRODUCTION';

// ─── Coin Config ─────────────────────────────────────────────────
const COIN = {
  name: 'RELAY Coin',
  symbol: '◈',
  short: 'RLC',
  signupBonus: 50,    // coins on new account
  referralBonus: 75,    // coins for both parties when referral used
  earnPer100: 10,    // coins earned per ₹100 spent
  redemptionRate: 1,     // 1 coin = ₹1 off
  minRedemption: 50,    // minimum coins to redeem at checkout
};

// ─── Security Middleware ──────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '10kb' }));  // reject oversized payloads
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate Limiters ────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts. Please wait 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const orderLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many requests. Please slow down.' },
});
app.use('/api/auth', authLimiter);
app.use('/api/admin/auth', authLimiter);
app.use('/api/orders', orderLimiter);

// ─── Data Layer (JSON file-based) ─────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');

function readData(file) {
  try {
    const fp = path.join(DATA_DIR, file);
    if (!fs.existsSync(fp)) return [];
    return JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch { return []; }
}
function writeData(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2), 'utf8');
}
function readAdmin() {
  const fp = path.join(DATA_DIR, 'admin.json');
  return fs.existsSync(fp) ? JSON.parse(fs.readFileSync(fp, 'utf8')) : null;
}

// ─── Audit Logger ─────────────────────────────────────────────────
function audit(action, details, ip) {
  const logs = readData('audit.json');
  logs.unshift({ action, details, ip: ip || 'unknown', ts: new Date().toISOString() });
  writeData('audit.json', logs.slice(0, 500));
}

// ─── Auth Middleware ──────────────────────────────────────────────
function verifyUser(req, res, next) {
  const token = req.cookies.user_token;
  if (!token) return res.status(401).json({ error: 'Login required.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie('user_token');
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

function verifyAdmin(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Admin access required.' });
  try {
    req.admin = jwt.verify(token, ADMIN_SECRET);
    next();
  } catch {
    res.clearCookie('admin_token');
    return res.status(401).json({ error: 'Admin session expired.' });
  }
}

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  next();
}

// ═════════════════════════════════════════════════════════════════
//  USER AUTH ROUTES
// ═════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register',
  body('name').trim().notEmpty().isLength({ max: 80 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6, max: 72 }),
  validate,
  async (req, res) => {
    try {
      const { name, email, password, referralCode } = req.body;
      const users = readData('users.json');

      if (users.find(u => u.email === email))
        return res.status(409).json({ error: 'Email already registered.' });

      const passwordHash = await bcrypt.hash(password, 12);

      // Generate unique referral code
      const slug = name.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 5);
      const myCode = slug + Math.random().toString(36).slice(2, 6).toUpperCase();

      let coins = COIN.signupBonus;

      // Process referral
      if (referralCode) {
        const referrer = users.find(u => u.referralCode === referralCode.toUpperCase());
        if (referrer) {
          coins += COIN.referralBonus;
          referrer.coins = (referrer.coins || 0) + COIN.referralBonus;
          writeData('users.json', users);
          audit('REFERRAL_BONUS', `${referrer.name} earned ${COIN.referralBonus} ◈ via referral`, req.ip);
        }
      }

      const newUser = {
        id: uuidv4(), name, email, passwordHash,
        referralCode: myCode,
        usedReferralCode: referralCode ? referralCode.toUpperCase() : null,
        coins,
        createdAt: new Date().toISOString(),
      };

      users.push(newUser);
      writeData('users.json', users);
      audit('USER_REGISTER', `${name} (${email})`, req.ip);

      const token = jwt.sign({ id: newUser.id, name, email }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('user_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({
        user: { id: newUser.id, name, email, coins: newUser.coins, referralCode: myCode },
        coin: COIN,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Registration failed. Try again.' });
    }
  }
);

// POST /api/auth/login
app.post('/api/auth/login',
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  validate,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const users = readData('users.json');
      const user = users.find(u => u.email === email);

      if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        audit('LOGIN_FAIL', email, req.ip);
        return res.status(401).json({ error: 'Invalid email or password.' });
      }

      const token = jwt.sign({ id: user.id, name: user.name, email }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('user_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      audit('USER_LOGIN', `${user.name}`, req.ip);

      res.json({
        user: { id: user.id, name: user.name, email, coins: user.coins, referralCode: user.referralCode },
        coin: COIN,
      });
    } catch (err) {
      res.status(500).json({ error: 'Login failed.' });
    }
  }
);

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('user_token');
  res.json({ message: 'Logged out.' });
});

// GET /api/auth/me
app.get('/api/auth/me', verifyUser, (req, res) => {
  const users = readData('users.json');
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({
    user: { id: user.id, name: user.name, email: user.email, coins: user.coins, referralCode: user.referralCode },
    coin: COIN,
  });
});

// ═════════════════════════════════════════════════════════════════
//  PRODUCTS
// ═════════════════════════════════════════════════════════════════

app.get('/api/products', (req, res) => {
  res.json({ products: readData('products.json'), coin: COIN });
});

// ═════════════════════════════════════════════════════════════════
//  PROMO CODE VALIDATION
// ═════════════════════════════════════════════════════════════════

app.post('/api/promo/validate', verifyUser,
  body('code').trim().notEmpty(),
  body('cartTotal').isNumeric(),
  validate,
  (req, res) => {
    const { code, cartTotal } = req.body;
    const promos = readData('promos.json');
    const promo = promos.find(p => p.code === code.toUpperCase() && p.active);

    if (!promo) return res.status(404).json({ error: 'Invalid or expired promo code.' });
    if (promo.maxUses && promo.usedCount >= promo.maxUses)
      return res.status(400).json({ error: 'Promo code usage limit reached.' });

    const discount = promo.type === 'percent'
      ? Math.floor(Number(cartTotal) * promo.value / 100)
      : promo.value;

    res.json({ valid: true, type: promo.type, value: promo.value, discount });
  }
);

// ═════════════════════════════════════════════════════════════════
//  ORDERS
// ═════════════════════════════════════════════════════════════════

app.post('/api/orders', verifyUser,
  body('items').isArray({ min: 1 }),
  body('customerName').trim().notEmpty().isLength({ max: 100 }).escape(),
  body('address').trim().notEmpty().isLength({ max: 600 }).escape(),
  validate,
  (req, res) => {
    const { items, customerName, address, promoCode, useCoins } = req.body;

    const users = readData('users.json');
    const products = readData('products.json');
    const orders = readData('orders.json');
    const promos = readData('promos.json');
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // Build items & subtotal
    let subtotal = 0;
    const orderItems = [];
    for (const item of items) {
      const p = products.find(x => x.id === item.id);
      if (!p) continue;
      const qty = Math.max(1, Math.min(10, parseInt(item.qty) || 1));
      orderItems.push({ id: p.id, title: p.title, img: p.img, price: p.price, qty });
      subtotal += p.price * qty;
    }
    if (!orderItems.length) return res.status(400).json({ error: 'No valid items in cart.' });

    // Apply promo
    let promoDiscount = 0;
    let appliedPromo = null;
    if (promoCode) {
      const promo = promos.find(p => p.code === promoCode.toUpperCase() && p.active);
      if (promo && (!promo.maxUses || promo.usedCount < promo.maxUses)) {
        promoDiscount = promo.type === 'percent'
          ? Math.floor(subtotal * promo.value / 100)
          : promo.value;
        promo.usedCount = (promo.usedCount || 0) + 1;
        appliedPromo = promo.code;
        writeData('promos.json', promos);
      }
    }

    // Apply coins
    let coinsUsed = 0;
    if (useCoins && user.coins >= COIN.minRedemption) {
      const maxRedeemable = Math.max(0, subtotal - promoDiscount);
      coinsUsed = Math.min(user.coins, maxRedeemable);
      user.coins -= coinsUsed;
    }

    const finalPrice = Math.max(0, subtotal - promoDiscount - coinsUsed);
    const coinsEarned = Math.floor(finalPrice / 100) * COIN.earnPer100;
    user.coins = (user.coins || 0) + coinsEarned;

    const order = {
      id: uuidv4(),
      userId: user.id,
      customerName,
      address,
      items: orderItems,
      subtotal,
      promoCode: appliedPromo,
      promoDiscount,
      coinsUsed,
      coinsEarned,
      finalPrice,
      status: 'relayed',
      relayedAt: new Date().toISOString(),
    };

    orders.unshift(order);
    writeData('orders.json', orders);
    writeData('users.json', users);
    audit('ORDER_RELAYED', `#${order.id.slice(0, 8)} — ${customerName} — ₹${finalPrice}`, req.ip);

    res.json({ success: true, orderId: order.id, coinsEarned, newCoinBalance: user.coins });
  }
);

// ═════════════════════════════════════════════════════════════════
//  ADMIN AUTH
// ═════════════════════════════════════════════════════════════════

app.post('/api/admin/auth/login',
  body('password').notEmpty(),
  validate,
  async (req, res) => {
    const adminData = readAdmin();
    if (!adminData) return res.status(500).json({ error: 'Admin not configured.' });

    const valid = await bcrypt.compare(req.body.password, adminData.passwordHash);
    if (!valid) {
      audit('ADMIN_LOGIN_FAIL', 'Failed attempt', req.ip);
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    const token = jwt.sign({ role: 'admin' }, ADMIN_SECRET, { expiresIn: '8h' });
    res.cookie('admin_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000,
    });
    audit('ADMIN_LOGIN', 'Admin authenticated', req.ip);
    res.json({ message: 'Admin authenticated.' });
  }
);

app.post('/api/admin/auth/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ message: 'Logged out.' });
});

app.get('/api/admin/auth/check', verifyAdmin, (req, res) => res.json({ ok: true }));

// ═════════════════════════════════════════════════════════════════
//  ADMIN — PRODUCTS
// ═════════════════════════════════════════════════════════════════

app.get('/api/admin/products', verifyAdmin, (req, res) =>
  res.json({ products: readData('products.json') })
);

app.post('/api/admin/products', verifyAdmin,
  body('title').trim().notEmpty().isLength({ max: 200 }).escape(),
  body('img').isURL(),
  body('price').isInt({ min: 1 }),
  validate,
  (req, res) => {
    const { title, img, price, hot } = req.body;
    const products = readData('products.json');
    const p = { id: Date.now(), title, img, price: parseInt(price), hot: !!hot, createdAt: new Date().toISOString() };
    products.unshift(p);
    writeData('products.json', products);
    audit('PRODUCT_ADDED', title, req.ip);
    res.json({ product: p });
  }
);

app.patch('/api/admin/products/:id', verifyAdmin, (req, res) => {
  const products = readData('products.json');
  const p = products.find(x => String(x.id) === req.params.id);
  if (!p) return res.status(404).json({ error: 'Product not found.' });
  if (req.body.hot !== undefined) p.hot = req.body.hot;
  if (req.body.title) p.title = req.body.title;
  if (req.body.price) p.price = parseInt(req.body.price);
  writeData('products.json', products);
  res.json({ product: p });
});

app.delete('/api/admin/products/:id', verifyAdmin, (req, res) => {
  let products = readData('products.json');
  products = products.filter(p => String(p.id) !== req.params.id);
  writeData('products.json', products);
  audit('PRODUCT_DELETED', req.params.id, req.ip);
  res.json({ success: true });
});

// ═════════════════════════════════════════════════════════════════
//  ADMIN — ORDERS
// ═════════════════════════════════════════════════════════════════

app.get('/api/admin/orders', verifyAdmin, (req, res) =>
  res.json({ orders: readData('orders.json') })
);

// ═════════════════════════════════════════════════════════════════
//  ADMIN — USERS
// ═════════════════════════════════════════════════════════════════

app.get('/api/admin/users', verifyAdmin, (req, res) => {
  const users = readData('users.json').map(u => ({
    id: u.id, name: u.name, email: u.email,
    coins: u.coins, referralCode: u.referralCode, createdAt: u.createdAt,
  }));
  res.json({ users, coin: COIN });
});

// ═════════════════════════════════════════════════════════════════
//  ADMIN — PROMO CODES
// ═════════════════════════════════════════════════════════════════

app.get('/api/admin/promos', verifyAdmin, (req, res) =>
  res.json({ promos: readData('promos.json') })
);

app.post('/api/admin/promos', verifyAdmin,
  body('code').trim().notEmpty().toUpperCase().isLength({ max: 20 }),
  body('type').isIn(['percent', 'flat']),
  body('value').isInt({ min: 1 }),
  validate,
  (req, res) => {
    const { code, type, value, maxUses } = req.body;
    const promos = readData('promos.json');
    const clean = code.toUpperCase().replace(/\s/g, '');
    if (promos.find(p => p.code === clean))
      return res.status(409).json({ error: 'Promo code already exists.' });
    const promo = {
      code: clean, type, value: parseInt(value),
      maxUses: maxUses || null, usedCount: 0,
      active: true, createdAt: new Date().toISOString(),
    };
    promos.unshift(promo);
    writeData('promos.json', promos);
    audit('PROMO_CREATED', clean, req.ip);
    res.json({ promo });
  }
);

app.delete('/api/admin/promos/:code', verifyAdmin, (req, res) => {
  let promos = readData('promos.json');
  promos = promos.filter(p => p.code !== req.params.code.toUpperCase());
  writeData('promos.json', promos);
  audit('PROMO_DELETED', req.params.code, req.ip);
  res.json({ success: true });
});

// ═════════════════════════════════════════════════════════════════
//  ADMIN — AUDIT LOG
// ═════════════════════════════════════════════════════════════════

app.get('/api/admin/audit', verifyAdmin, (req, res) =>
  res.json({ logs: readData('audit.json').slice(0, 200) })
);

// ═════════════════════════════════════════════════════════════════
//  DEFAULT DATA
// ═════════════════════════════════════════════════════════════════

const DEFAULT_PRODUCTS = [
  { id: 1, title: 'Hand-Stitched Leather Wallet', img: 'https://images.unsplash.com/photo-1586363104862-3a5e2ab60d99?w=600&q=80', price: 1299, hot: true, createdAt: new Date().toISOString() },
  { id: 2, title: 'Artisan Ceramic Mug', img: 'https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?w=600&q=80', price: 649, hot: true, createdAt: new Date().toISOString() },
  { id: 3, title: 'Woven Cotton Tote Bag', img: 'https://images.unsplash.com/photo-1532947974658-e22c44e20b63?w=600&q=80', price: 899, hot: false, createdAt: new Date().toISOString() },
  { id: 4, title: 'Pressed Botanical Print', img: 'https://images.unsplash.com/photo-1585241936937-a2f46e29be9e?w=600&q=80', price: 1599, hot: false, createdAt: new Date().toISOString() },
  { id: 5, title: 'Pure Beeswax Candle Set', img: 'https://images.unsplash.com/photo-1602612594946-9c4af32cf28a?w=600&q=80', price: 799, hot: true, createdAt: new Date().toISOString() },
  { id: 6, title: 'Handmade Macramé Wall Art', img: 'https://images.unsplash.com/photo-1615971677499-5467cbab01b0?w=600&q=80', price: 2199, hot: false, createdAt: new Date().toISOString() },
];

const DEFAULT_PROMOS = [
  { code: 'RELAY10', type: 'percent', value: 10, maxUses: 100, usedCount: 0, active: true, createdAt: new Date().toISOString() },
  { code: 'WELCOME50', type: 'flat', value: 50, maxUses: 500, usedCount: 0, active: true, createdAt: new Date().toISOString() },
];

// ═════════════════════════════════════════════════════════════════
//  INITIALIZE & START
// ═════════════════════════════════════════════════════════════════

async function init() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

  // Admin account with bcrypt-hashed password
  const adminFile = path.join(DATA_DIR, 'admin.json');
  if (!fs.existsSync(adminFile)) {
    const hash = await bcrypt.hash('relay2024', 12);
    fs.writeFileSync(adminFile, JSON.stringify({ passwordHash: hash }, null, 2));
    console.log('\n✓  Admin initialized.');
    console.log('   Default password : relay2024');
    console.log('⚠  CHANGE THIS IN PRODUCTION!\n');
  }

  const pf = path.join(DATA_DIR, 'products.json');
  if (!fs.existsSync(pf)) writeData('products.json', DEFAULT_PRODUCTS);

  const prf = path.join(DATA_DIR, 'promos.json');
  if (!fs.existsSync(prf)) {
    writeData('promos.json', DEFAULT_PROMOS);
    console.log('✓  Default promo codes: RELAY10 (10% off), WELCOME50 (₹50 off)');
  }

  ['users.json', 'orders.json', 'audit.json'].forEach(f => {
    if (!fs.existsSync(path.join(DATA_DIR, f))) writeData(f, []);
  });

  app.listen(PORT, () => {
    console.log(`\n🚀  RELAY. Server  →  http://localhost:${PORT}`);
    console.log(`    Admin Panel    →  http://localhost:${PORT}/admin.html\n`);
  });
}

init().catch(err => { console.error('Startup error:', err); process.exit(1); });
