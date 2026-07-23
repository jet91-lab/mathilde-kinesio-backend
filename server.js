require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const apn = require('@parse/node-apn');
const { MongoClient } = require('mongodb');
const Stripe = require('stripe');

const app = express();
// Derrière le proxy Render : nécessaire pour que express-rate-limit
// identifie la vraie IP client (X-Forwarded-For)
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: [FRONTEND_URL, 'http://localhost:3000', 'http://127.0.0.1:5500'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── STRIPE (bons cadeaux) ───────────────────────────────────────────────────────
// Le webhook a besoin du corps brut (non parsé) pour vérifier la signature
// Stripe : sa route doit donc être déclarée AVANT app.use(express.json()),
// qui parserait sinon le body en JSON avant qu'on puisse le vérifier.
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(503).send('Stripe non configuré');

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook signature invalide : ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    try {
      const existing = await db.collection('giftCertificates').findOne({ stripeSessionId: session.id });
      if (!existing) {
        const meta = session.metadata || {};
        const now = new Date();
        const expires = new Date(now);
        expires.setFullYear(expires.getFullYear() + 1);

        const cert = {
          id: uuidv4(),
          code: await generateUniqueGiftCode(),
          type: meta.type,
          amount: (session.amount_total || 0) / 100,
          purchaserName: meta.purchaserName || '',
          purchaserEmail: session.customer_details?.email || meta.purchaserEmail || '',
          recipientName: meta.recipientName || '',
          message: meta.message || '',
          status: 'paid',
          stripeSessionId: session.id,
          createdAt: now.toISOString(),
          expiresAt: expires.toISOString(),
          redeemedAt: null,
          redeemedBookingId: null,
        };
        await db.collection('giftCertificates').insertOne(cert);
        sendPush(
          'Bon cadeau vendu 🎁',
          `${TYPE_LABELS[cert.type] || cert.type} — ${cert.amount} € pour ${cert.recipientName || cert.purchaserName}`
        ).catch(e => console.error('Erreur envoi push bon cadeau :', e.message));
      }
    } catch (e) {
      console.error('Erreur traitement webhook Stripe :', e.message);
      return res.status(500).send('Erreur interne');
    }
  }

  res.json({ received: true });
});

app.use(express.json());

// ── RATE LIMITING ─────────────────────────────────────────────────────────────
// Réservations : 10 tentatives par IP par heure
app.use('/api/book', rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Trop de tentatives, réessayez dans une heure.' },
  standardHeaders: true,
  legacyHeaders: false,
}));

// Connexion admin : 5 tentatives par IP par 15 minutes
app.use('/api/admin/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Trop de tentatives de connexion, réessayez dans 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
}));

// Créneaux : 60 requêtes par IP par minute (navigation calendrier)
app.use('/api/slots', rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Trop de requêtes, réessayez dans une minute.' },
  standardHeaders: true,
  legacyHeaders: false,
}));

// ── BASE DE DONNÉES (MongoDB Atlas) ─────────────────────────────────────────────
// Le disque local de Render (offre gratuite/Starter) est éphémère : tout fichier
// écrit sur disque est perdu à chaque redémarrage du serveur. D'où le passage à
// une vraie base de données persistante plutôt que des fichiers JSON.
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || 'equilibre';

let db = null;
let mongoClient = null;

const NO_ID_PROJECTION = { projection: { _id: 0 } };
const DEFAULT_PREFS = { newBooking: true, dailyRecap: true, dailyRecapTime: '19:00', lastRecapSentDate: null };

async function getPrefs() {
  const doc = await db.collection('prefs').findOne({ _id: 'notification-prefs' });
  return { ...DEFAULT_PREFS, ...(doc || {}) };
}

async function savePrefs(prefs) {
  await db.collection('prefs').updateOne(
    { _id: 'notification-prefs' },
    { $set: prefs },
    { upsert: true }
  );
}

// ── DISPONIBILITÉS DE BASE ────────────────────────────────────────────────────
// 0=dim 1=lun 2=mar 3=mer 4=jeu 5=ven 6=sam
const WORKING_DAYS = [1, 3, 5]; // lun, mer, ven
const WORK_START = '09:00';
const WORK_END   = '18:00';
const LUNCH_START = '12:30';
const LUNCH_END   = '14:00';
const GAP_MINUTES = 15; // intervalle entre RDV

const SESSION_DURATIONS = {
  'decouverte':  60,  // 1h
  'ado':         60,  // 1h
  'kinesio':     90,  // 1h30
  'aromatouch':  60,  // 1h
};

// Doit rester aligné avec SessionPricing.swift (app) et les tarifs affichés sur le site.
const SESSION_PRICES = {
  'decouverte':  50,
  'ado':         50,
  'kinesio':     70,
  'aromatouch':  70,
};

const TYPE_LABELS = {
  decouverte: 'Découverte',
  ado:        'Ado',
  kinesio:    'Kinésio',
  aromatouch: 'AromaTouch',
};

// Sans caractères ambigus (0/O, 1/I/L) pour rester lisible sur un bon imprimé.
const GIFT_CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generateGiftCode() {
  let raw = '';
  for (let i = 0; i < 8; i++) raw += GIFT_CODE_CHARS[Math.floor(Math.random() * GIFT_CODE_CHARS.length)];
  return `EQUI-${raw.slice(0, 4)}-${raw.slice(4)}`;
}

async function generateUniqueGiftCode() {
  let code;
  do {
    code = generateGiftCode();
  } while (await db.collection('giftCertificates').findOne({ code }));
  return code;
}

function timeToMinutes(t) {
  const [h, m] = t.split(':').map(Number);
  return h * 60 + m;
}

function minutesToTime(mins) {
  const h = Math.floor(mins / 60).toString().padStart(2, '0');
  const m = (mins % 60).toString().padStart(2, '0');
  return `${h}:${m}`;
}

// Retourne tous les créneaux potentiels d'une journée (sans tenir compte des blocages)
function generateDaySlots(dateStr, durationMinutes) {
  const date = new Date(dateStr + 'T00:00:00');
  const dow = date.getDay();
  if (!WORKING_DAYS.includes(dow)) return [];

  const slots = [];
  const start = timeToMinutes(WORK_START);
  const end   = timeToMinutes(WORK_END);
  const lStart = timeToMinutes(LUNCH_START);
  const lEnd   = timeToMinutes(LUNCH_END);

  let cur = start;
  while (cur + durationMinutes <= end) {
    const slotEnd = cur + durationMinutes;
    // Pas chevauchement avec pause déjeuner
    const overlapsLunch = cur < lEnd && slotEnd > lStart;
    if (!overlapsLunch) {
      slots.push({ start: minutesToTime(cur), end: minutesToTime(slotEnd) });
    }
    cur += durationMinutes + GAP_MINUTES;
  }
  return slots;
}

// ── NOTIFICATIONS PUSH (APNs) ─────────────────────────────────────────────────
// Config à définir dans les variables d'env Render une fois la clé APNs générée
// depuis le compte développeur Apple : APN_KEY (contenu du .p8, ou APN_KEY_PATH
// vers un fichier), APN_KEY_ID, APN_TEAM_ID, APN_BUNDLE_ID, APN_PRODUCTION=true.
//
// node-apn traite toute valeur `string` passée à `token.key` comme un CHEMIN
// DE FICHIER (fs.readFileSync dessus) — jamais comme le contenu brut de la
// clé. Donc si on fournit le contenu du .p8 via APN_KEY, il faut le passer en
// Buffer pour qu'il soit traité comme des données, pas comme un chemin.
function resolveAPNKey() {
  if (process.env.APN_KEY_PATH) return process.env.APN_KEY_PATH;
  if (!process.env.APN_KEY) return null;
  const normalized = process.env.APN_KEY.includes('\\n')
    ? process.env.APN_KEY.replace(/\\n/g, '\n')
    : process.env.APN_KEY;
  return Buffer.from(normalized, 'utf8');
}

let apnProvider = null;
const apnKey = resolveAPNKey();
if (process.env.APN_KEY_ID && process.env.APN_TEAM_ID && apnKey) {
  try {
    apnProvider = new apn.Provider({
      token: {
        key: apnKey,
        keyId: process.env.APN_KEY_ID,
        teamId: process.env.APN_TEAM_ID,
      },
      production: process.env.APN_PRODUCTION === 'true',
    });
    console.log('APNs configuré.');
  } catch (e) {
    console.error('Erreur de configuration APNs :', e.message);
  }
} else {
  console.log('APNs non configuré (variables d\'env manquantes) — notifications push désactivées.');
}

async function sendPush(title, body) {
  if (!apnProvider) return;
  const devices = await db.collection('devices').find({}, NO_ID_PROJECTION).toArray();
  if (!devices.length) return;

  const note = new apn.Notification();
  note.alert = { title, body };
  note.sound = 'default';
  note.topic = process.env.APN_BUNDLE_ID;

  const result = await apnProvider.send(note, devices.map(d => d.deviceToken));

  // Purge les tokens invalides (désinstallation, expiration…)
  const invalidTokens = result.failed
    .filter(f => ['BadDeviceToken', 'Unregistered'].includes(f.response?.reason))
    .map(f => f.device);
  if (invalidTokens.length) {
    await db.collection('devices').deleteMany({ deviceToken: { $in: invalidTokens } });
  }
}

// ── RÉCAP QUOTIDIEN ────────────────────────────────────────────────────────────
// Vérifie chaque minute si c'est l'heure d'envoyer le récap du lendemain.
// Nécessite que le fuseau du serveur Render corresponde à Europe/Paris
// (variable d'env TZ=Europe/Paris) pour que l'heure choisie soit correcte.
async function checkDailyRecap() {
  const prefs = await getPrefs();
  if (!prefs.dailyRecap) return;

  const now = new Date();
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const currentTime = `${hh}:${mm}`;
  const today = now.toISOString().slice(0, 10);

  if (currentTime !== prefs.dailyRecapTime || prefs.lastRecapSentDate === today) return;

  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const tomorrowStr = tomorrow.toISOString().slice(0, 10);

  const bookings = (await db.collection('bookings')
    .find({ date: tomorrowStr, status: { $ne: 'cancelled' } }, NO_ID_PROJECTION)
    .toArray())
    .sort((a, b) => a.startTime.localeCompare(b.startTime));

  await savePrefs({ ...prefs, lastRecapSentDate: today });

  if (!bookings.length) return;

  const list = bookings.map(b => `${b.startTime.replace(':00', 'h')} ${b.firstName} ${b.lastName[0]}.`).join(', ');
  sendPush(`Demain : ${bookings.length} RDV`, list).catch(e => console.error('Erreur envoi récap :', e.message));
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  try {
    req.admin = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

// ── ROUTES PUBLIQUES ──────────────────────────────────────────────────────────

// GET /api/slots?date=YYYY-MM-DD&type=premiere|suivi&excludeId=... (excludeId : pour
// laisser réapparaître le créneau d'une réservation en cours de modification)
app.get('/api/slots', async (req, res) => {
  const { date, type = 'suivi', excludeId } = req.query;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: 'Paramètre date invalide (YYYY-MM-DD)' });
  }
  const duration = SESSION_DURATIONS[type] || 60;
  const allSlots = generateDaySlots(date, duration);

  if (allSlots.length === 0) {
    return res.json({ date, slots: [] });
  }

  const bookingFilter = { date, status: { $ne: 'cancelled' } };
  if (excludeId) bookingFilter.id = { $ne: excludeId };
  const bookings = await db.collection('bookings').find(bookingFilter, NO_ID_PROJECTION).toArray();
  const blocks   = await db.collection('blocks').find({}, NO_ID_PROJECTION).toArray();

  // Construire liste des intervalles occupés ce jour-là
  const busyIntervals = [];

  // Réservations confirmées
  for (const b of bookings) {
    busyIntervals.push({
      start: timeToMinutes(b.startTime),
      end:   timeToMinutes(b.endTime),
    });
  }

  // Blocages (ponctuels, journée entière, récurrents)
  const dateObj = new Date(date + 'T00:00:00');
  const dow = dateObj.getDay();

  for (const bl of blocks) {
    if (bl.type === 'day' && bl.date === date) {
      busyIntervals.push({ start: 0, end: 1440 });
    } else if (bl.type === 'slot' && bl.date === date) {
      busyIntervals.push({
        start: timeToMinutes(bl.startTime),
        end:   timeToMinutes(bl.endTime),
      });
    } else if (bl.type === 'recurring') {
      // Vérifier si la récurrence s'applique à cette date
      const recStart = new Date(bl.startDate + 'T00:00:00');
      const recEnd   = bl.endDate ? new Date(bl.endDate + 'T00:00:00') : null;
      if (dateObj >= recStart && (!recEnd || dateObj <= recEnd)) {
        if (bl.dayOfWeek === dow) {
          busyIntervals.push({
            start: timeToMinutes(bl.startTime),
            end:   timeToMinutes(bl.endTime),
          });
        }
      }
    }
  }

  // Filtrer les créneaux disponibles
  const available = allSlots.filter(slot => {
    const sStart = timeToMinutes(slot.start);
    const sEnd   = timeToMinutes(slot.end);
    return !busyIntervals.some(busy =>
      sStart < busy.end && sEnd > busy.start
    );
  });

  res.json({ date, type, slots: available });
});

// Vérifie qu'un créneau (date/startTime/endTime) est libre : ni réservé par une
// autre réservation confirmée, ni bloqué. `excludeBookingId` permet à une
// réservation d'ignorer son propre créneau lors d'une modification.
async function checkSlotAvailable(date, startTime, endTime, type, excludeBookingId = null) {
  const duration = SESSION_DURATIONS[type] || 60;
  const allSlots = generateDaySlots(date, duration);
  const slotExists = allSlots.some(s => s.start === startTime && s.end === endTime);
  if (!slotExists) {
    return 'Ce créneau n\'est pas disponible pour ce type de séance';
  }

  const bookings = await db.collection('bookings').find({ date }, NO_ID_PROJECTION).toArray();
  const blocks   = await db.collection('blocks').find({}, NO_ID_PROJECTION).toArray();
  const dateObj  = new Date(date + 'T00:00:00');
  const dow      = dateObj.getDay();
  const reqStart = timeToMinutes(startTime);
  const reqEnd   = timeToMinutes(endTime);

  // Conflits réservations
  const conflict = bookings.some(b =>
    b.status !== 'cancelled' &&
    b.id !== excludeBookingId &&
    reqStart < timeToMinutes(b.endTime) &&
    reqEnd   > timeToMinutes(b.startTime)
  );
  if (conflict) {
    return 'Ce créneau vient d\'être réservé';
  }

  // Conflits blocages
  for (const bl of blocks) {
    if (bl.type === 'day' && bl.date === date) {
      return 'Cette journée est bloquée';
    }
    if (bl.type === 'slot' && bl.date === date) {
      const bStart = timeToMinutes(bl.startTime);
      const bEnd   = timeToMinutes(bl.endTime);
      if (reqStart < bEnd && reqEnd > bStart) {
        return 'Ce créneau est bloqué';
      }
    }
    if (bl.type === 'recurring') {
      const recStart = new Date(bl.startDate + 'T00:00:00');
      const recEnd   = bl.endDate ? new Date(bl.endDate + 'T00:00:00') : null;
      if (dateObj >= recStart && (!recEnd || dateObj <= recEnd) && bl.dayOfWeek === dow) {
        const bStart = timeToMinutes(bl.startTime);
        const bEnd   = timeToMinutes(bl.endTime);
        if (reqStart < bEnd && reqEnd > bStart) {
          return 'Ce créneau est bloqué';
        }
      }
    }
  }

  return null;
}

// Vérifie qu'un code cadeau existe, est encore valide (payé, non utilisé, non expiré)
// et correspond bien au type de séance réservé (le montant payé doit couvrir le type choisi).
async function validateGiftCode(code, type) {
  const cert = await db.collection('giftCertificates').findOne({ code: code.trim().toUpperCase() });
  if (!cert) return 'Code cadeau introuvable';
  if (cert.status === 'redeemed') return 'Ce bon cadeau a déjà été utilisé';
  if (new Date(cert.expiresAt) < new Date()) return 'Ce bon cadeau a expiré';
  if (cert.type !== type) return `Ce bon cadeau est valable uniquement pour une séance « ${TYPE_LABELS[cert.type] || cert.type} »`;
  return null;
}

// POST /api/book
app.post('/api/book', async (req, res) => {
  const { date, startTime, endTime, type, firstName, lastName, email, phone, giftCode } = req.body;

  // Validation basique
  if (!date || !startTime || !endTime || !type || !firstName || !lastName || !email || !phone) {
    return res.status(400).json({ error: 'Champs manquants' });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: 'Date invalide' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Email invalide' });
  }

  const conflictError = await checkSlotAvailable(date, startTime, endTime, type);
  if (conflictError) {
    return res.status(409).json({ error: conflictError });
  }

  let giftCert = null;
  if (giftCode) {
    const codeError = await validateGiftCode(giftCode, type);
    if (codeError) return res.status(400).json({ error: codeError });
    giftCert = giftCode.trim().toUpperCase();
  }

  const booking = {
    id: uuidv4(),
    date,
    startTime,
    endTime,
    type,
    firstName: firstName.trim(),
    lastName:  lastName.trim(),
    email:     email.trim().toLowerCase(),
    phone:     phone.trim(),
    status: 'confirmed',
    giftCode: giftCert,
    createdAt: new Date().toISOString(),
  };

  await db.collection('bookings').insertOne(booking);
  delete booking._id;

  if (giftCert) {
    await db.collection('giftCertificates').updateOne(
      { code: giftCert },
      { $set: { status: 'redeemed', redeemedAt: new Date().toISOString(), redeemedBookingId: booking.id } }
    );
  }

  res.status(201).json({
    success: true,
    bookingId: booking.id,
    message: 'Réservation confirmée',
  });

  const prefs = await getPrefs();
  if (prefs.newBooking) {
    const typeLabel = TYPE_LABELS[type] || type;
    sendPush(
      'Nouveau RDV',
      `${booking.firstName} ${booking.lastName} — ${booking.date} à ${booking.startTime} (${typeLabel})`
    ).catch(e => console.error('Erreur envoi push :', e.message));
  }
});

// ── ROUTES ADMIN ──────────────────────────────────────────────────────────────

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Mot de passe incorrect' });
  }
  // 30 jours : usage quotidien depuis l'app mobile en plus du web
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

// GET /api/admin/bookings?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/api/admin/bookings', requireAuth, async (req, res) => {
  const { from, to, status } = req.query;
  const filter = {};
  if (from || to) {
    filter.date = {};
    if (from) filter.date.$gte = from;
    if (to)   filter.date.$lte = to;
  }
  if (status) filter.status = status;

  const bookings = await db.collection('bookings').find(filter, NO_ID_PROJECTION).toArray();
  bookings.sort((a, b) => a.date.localeCompare(b.date) || a.startTime.localeCompare(b.startTime));
  res.json(bookings);
});

// POST /api/admin/bookings — création manuelle par Mathilde depuis l'app.
// Distincte de /api/book (publique) : pas de limite de débit, et pas de
// notification push (inutile de s'auto-alerter d'un RDV qu'on vient de saisir).
app.post('/api/admin/bookings', requireAuth, async (req, res) => {
  const { date, startTime, endTime, type, firstName, lastName, email, phone } = req.body;

  if (!date || !startTime || !endTime || !type || !firstName || !lastName || !email || !phone) {
    return res.status(400).json({ error: 'Champs manquants' });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: 'Date invalide' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Email invalide' });
  }

  const conflictError = await checkSlotAvailable(date, startTime, endTime, type);
  if (conflictError) {
    return res.status(409).json({ error: conflictError });
  }

  const booking = {
    id: uuidv4(),
    date,
    startTime,
    endTime,
    type,
    firstName: firstName.trim(),
    lastName:  lastName.trim(),
    email:     email.trim().toLowerCase(),
    phone:     phone.trim(),
    status: 'confirmed',
    createdAt: new Date().toISOString(),
  };

  await db.collection('bookings').insertOne(booking);
  delete booking._id;
  res.status(201).json({ success: true, bookingId: booking.id });
});

// POST /api/admin/bookings/:id/cancel
app.post('/api/admin/bookings/:id/cancel', requireAuth, async (req, res) => {
  const result = await db.collection('bookings').updateOne(
    { id: req.params.id },
    { $set: { status: 'cancelled', cancelledAt: new Date().toISOString() } }
  );
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Réservation introuvable' });
  res.json({ success: true });
});

// PUT /api/admin/bookings/:id — reprogrammer / corriger une réservation
app.put('/api/admin/bookings/:id', requireAuth, async (req, res) => {
  const existing = await db.collection('bookings').findOne({ id: req.params.id }, NO_ID_PROJECTION);
  if (!existing) return res.status(404).json({ error: 'Réservation introuvable' });

  const { date, startTime, endTime, type, firstName, lastName, email, phone } = req.body;

  if (!date || !startTime || !endTime || !type || !firstName || !lastName || !email || !phone) {
    return res.status(400).json({ error: 'Champs manquants' });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: 'Date invalide' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Email invalide' });
  }

  const conflictError = await checkSlotAvailable(date, startTime, endTime, type, existing.id);
  if (conflictError) {
    return res.status(409).json({ error: conflictError });
  }

  const updated = {
    date,
    startTime,
    endTime,
    type,
    firstName: firstName.trim(),
    lastName:  lastName.trim(),
    email:     email.trim().toLowerCase(),
    phone:     phone.trim(),
  };

  await db.collection('bookings').updateOne({ id: req.params.id }, { $set: updated });
  res.json({ success: true, booking: { ...existing, ...updated } });
});

// GET /api/admin/blocks
app.get('/api/admin/blocks', requireAuth, async (req, res) => {
  res.json(await db.collection('blocks').find({}, NO_ID_PROJECTION).toArray());
});

// POST /api/admin/block
app.post('/api/admin/block', requireAuth, async (req, res) => {
  const { type, date, startTime, endTime, startDate, endDate, dayOfWeek, reason } = req.body;

  if (!type || !['day', 'slot', 'recurring'].includes(type)) {
    return res.status(400).json({ error: 'Type invalide (day | slot | recurring)' });
  }

  const block = { id: uuidv4(), type, reason: reason || '', createdAt: new Date().toISOString() };

  if (type === 'day') {
    if (!date) return res.status(400).json({ error: 'Date requise' });
    block.date = date;
  } else if (type === 'slot') {
    if (!date || !startTime || !endTime) return res.status(400).json({ error: 'Date, startTime et endTime requis' });
    block.date = date;
    block.startTime = startTime;
    block.endTime   = endTime;
  } else if (type === 'recurring') {
    if (!startDate || !startTime || !endTime || dayOfWeek === undefined) {
      return res.status(400).json({ error: 'startDate, startTime, endTime, dayOfWeek requis' });
    }
    block.startDate  = startDate;
    block.endDate    = endDate || null;
    block.startTime  = startTime;
    block.endTime    = endTime;
    block.dayOfWeek  = Number(dayOfWeek);
  }

  await db.collection('blocks').insertOne(block);
  delete block._id;
  res.status(201).json({ success: true, block });
});

// PUT /api/admin/blocks/:id — modifier un blocage existant
app.put('/api/admin/blocks/:id', requireAuth, async (req, res) => {
  const existing = await db.collection('blocks').findOne({ id: req.params.id }, NO_ID_PROJECTION);
  if (!existing) return res.status(404).json({ error: 'Blocage introuvable' });

  const { type, date, startTime, endTime, startDate, endDate, dayOfWeek, reason } = req.body;

  if (!type || !['day', 'slot', 'recurring'].includes(type)) {
    return res.status(400).json({ error: 'Type invalide (day | slot | recurring)' });
  }

  const updated = { type, reason: reason || '' };

  if (type === 'day') {
    if (!date) return res.status(400).json({ error: 'Date requise' });
    updated.date = date;
  } else if (type === 'slot') {
    if (!date || !startTime || !endTime) return res.status(400).json({ error: 'Date, startTime et endTime requis' });
    updated.date = date;
    updated.startTime = startTime;
    updated.endTime = endTime;
  } else if (type === 'recurring') {
    if (!startDate || !startTime || !endTime || dayOfWeek === undefined) {
      return res.status(400).json({ error: 'startDate, startTime, endTime, dayOfWeek requis' });
    }
    updated.startDate = startDate;
    updated.endDate = endDate || null;
    updated.startTime = startTime;
    updated.endTime = endTime;
    updated.dayOfWeek = Number(dayOfWeek);
  }

  await db.collection('blocks').replaceOne({ id: req.params.id }, { id: existing.id, ...updated, createdAt: existing.createdAt });
  res.json({ success: true, block: { id: existing.id, ...updated, createdAt: existing.createdAt } });
});

// DELETE /api/admin/blocks/:id
app.delete('/api/admin/blocks/:id', requireAuth, async (req, res) => {
  const result = await db.collection('blocks').deleteOne({ id: req.params.id });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Blocage introuvable' });
  res.json({ success: true });
});

// ── APPAREILS (notifications push) ─────────────────────────────────────────────

// POST /api/admin/device-token
app.post('/api/admin/device-token', requireAuth, async (req, res) => {
  const { deviceToken, platform, label } = req.body;
  if (!deviceToken) return res.status(400).json({ error: 'deviceToken requis' });

  await db.collection('devices').updateOne(
    { deviceToken },
    {
      $set: { platform: platform || 'ios', label: label || '' },
      $setOnInsert: { deviceToken, registeredAt: new Date().toISOString() },
    },
    { upsert: true }
  );
  res.status(201).json({ success: true });
});

// DELETE /api/admin/device-token/:token
app.delete('/api/admin/device-token/:token', requireAuth, async (req, res) => {
  await db.collection('devices').deleteOne({ deviceToken: req.params.token });
  res.json({ success: true });
});

// ── BONS CADEAUX ──────────────────────────────────────────────────────────────

// POST /api/gift-certificates/checkout — crée une session de paiement Stripe
app.post('/api/gift-certificates/checkout', async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Paiement en ligne indisponible pour le moment' });

  const { type, recipientName, message, purchaserName, purchaserEmail } = req.body;

  if (!type || !SESSION_PRICES[type]) {
    return res.status(400).json({ error: 'Type de séance invalide' });
  }
  if (!purchaserName || !purchaserEmail) {
    return res.status(400).json({ error: 'Nom et email requis' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(purchaserEmail)) {
    return res.status(400).json({ error: 'Email invalide' });
  }

  const amount = SESSION_PRICES[type];
  // Origine du site appelant, pour rediriger après paiement vers le même domaine
  // (utile aussi bien en prod qu'en test local).
  const origin = req.headers.origin || 'https://alequilibre-kinesio.fr';

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      payment_method_types: ['card'],
      customer_email: purchaserEmail,
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: {
            name: `Bon cadeau — ${TYPE_LABELS[type]}`,
            description: 'À l\'équilibre · Mathilde Bourgoin',
          },
          unit_amount: Math.round(amount * 100),
        },
        quantity: 1,
      }],
      metadata: {
        type,
        recipientName: (recipientName || '').slice(0, 200),
        message: (message || '').slice(0, 500),
        purchaserName: purchaserName.slice(0, 200),
        purchaserEmail,
      },
      success_url: `${origin}/cadeau-succes.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/cadeau.html`,
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('Erreur création session Stripe :', e.message);
    res.status(500).json({ error: 'Impossible de créer le paiement pour le moment' });
  }
});

// GET /api/gift-certificates/session/:sessionId — la page de succès l'interroge
// pour afficher le code une fois le webhook traité (peut arriver quelques
// secondes après la redirection).
app.get('/api/gift-certificates/session/:sessionId', async (req, res) => {
  const cert = await db.collection('giftCertificates').findOne({ stripeSessionId: req.params.sessionId }, NO_ID_PROJECTION);
  if (!cert) return res.status(404).json({ error: 'pending' });
  res.json(cert);
});

// GET /api/admin/gift-certificates
app.get('/api/admin/gift-certificates', requireAuth, async (req, res) => {
  const certs = await db.collection('giftCertificates').find({}, NO_ID_PROJECTION).toArray();
  certs.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json(certs);
});

// POST /api/admin/gift-certificates/:code/redeem — usage manuel (code présenté en personne)
app.post('/api/admin/gift-certificates/:code/redeem', requireAuth, async (req, res) => {
  const code = req.params.code.trim().toUpperCase();
  const cert = await db.collection('giftCertificates').findOne({ code });
  if (!cert) return res.status(404).json({ error: 'Bon cadeau introuvable' });
  if (cert.status === 'redeemed') return res.status(409).json({ error: 'Ce bon cadeau a déjà été utilisé' });

  await db.collection('giftCertificates').updateOne(
    { code },
    { $set: { status: 'redeemed', redeemedAt: new Date().toISOString() } }
  );
  res.json({ success: true });
});

// ── CLIENTS ────────────────────────────────────────────────────────────────────

// GET /api/admin/clients — liste agrégée depuis les réservations + notes
app.get('/api/admin/clients', requireAuth, async (req, res) => {
  const bookings = await db.collection('bookings').find({}, NO_ID_PROJECTION).toArray();
  const clientsNotes = await db.collection('clients').find({}, NO_ID_PROJECTION).toArray();

  const byEmail = new Map();
  for (const b of bookings) {
    const existing = byEmail.get(b.email);
    if (!existing || b.date > existing.lastSessionDate) {
      byEmail.set(b.email, {
        email: b.email,
        firstName: b.firstName,
        lastName: b.lastName,
        phone: b.phone,
        lastSessionDate: b.date,
        totalSessions: (existing ? existing.totalSessions : 0) + 1,
      });
    } else {
      existing.totalSessions += 1;
    }
  }

  const clients = Array.from(byEmail.values()).map(c => {
    const profile = clientsNotes.find(n => n.email === c.email);
    return {
      ...c,
      firstName: profile?.firstName || c.firstName,
      lastName:  profile?.lastName  || c.lastName,
      phone:     profile?.phone     || c.phone,
      notes: profile ? profile.notes || '' : '',
    };
  });

  clients.sort((a, b) => b.lastSessionDate.localeCompare(a.lastSessionDate));
  res.json(clients);
});

// GET /api/admin/clients/:email — fiche détaillée
app.get('/api/admin/clients/:email', requireAuth, async (req, res) => {
  const email = req.params.email.toLowerCase();
  const bookings = (await db.collection('bookings').find({ email }, NO_ID_PROJECTION).toArray())
    .sort((a, b) => b.date.localeCompare(a.date) || b.startTime.localeCompare(a.startTime));

  if (!bookings.length) return res.status(404).json({ error: 'Client introuvable' });

  const profile = await db.collection('clients').findOne({ email }, NO_ID_PROJECTION);
  const latest = bookings[0];

  res.json({
    email,
    firstName: profile?.firstName || latest.firstName,
    lastName:  profile?.lastName  || latest.lastName,
    phone:     profile?.phone     || latest.phone,
    notes: profile ? profile.notes || '' : '',
    bookings,
  });
});

// PUT /api/admin/clients/:email/profile — corrige prénom/nom/téléphone
app.put('/api/admin/clients/:email/profile', requireAuth, async (req, res) => {
  const email = req.params.email.toLowerCase();
  const { firstName, lastName, phone } = req.body;

  const update = { updatedAt: new Date().toISOString() };
  if (typeof firstName === 'string' && firstName.trim()) update.firstName = firstName.trim();
  if (typeof lastName === 'string' && lastName.trim())   update.lastName  = lastName.trim();
  if (typeof phone === 'string' && phone.trim())         update.phone    = phone.trim();

  await db.collection('clients').updateOne(
    { email },
    { $set: update, $setOnInsert: { email } },
    { upsert: true }
  );
  res.json({ success: true });
});

// PUT /api/admin/clients/:email/notes
app.put('/api/admin/clients/:email/notes', requireAuth, async (req, res) => {
  const email = req.params.email.toLowerCase();
  const { notes } = req.body;
  if (typeof notes !== 'string') return res.status(400).json({ error: 'notes requis (string)' });

  await db.collection('clients').updateOne(
    { email },
    { $set: { notes, updatedAt: new Date().toISOString() }, $setOnInsert: { email } },
    { upsert: true }
  );
  res.json({ success: true });
});

// ── PRÉFÉRENCES DE NOTIFICATION ─────────────────────────────────────────────────

// GET /api/admin/notification-prefs
app.get('/api/admin/notification-prefs', requireAuth, async (req, res) => {
  const { lastRecapSentDate, ...prefs } = await getPrefs();
  res.json(prefs);
});

// PUT /api/admin/notification-prefs
app.put('/api/admin/notification-prefs', requireAuth, async (req, res) => {
  const { newBooking, dailyRecap, dailyRecapTime } = req.body;

  if (dailyRecapTime !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(dailyRecapTime)) {
    return res.status(400).json({ error: 'dailyRecapTime invalide (format HH:MM)' });
  }

  const prefs = await getPrefs();
  if (typeof newBooking === 'boolean') prefs.newBooking = newBooking;
  if (typeof dailyRecap === 'boolean') prefs.dailyRecap = dailyRecap;
  if (dailyRecapTime) prefs.dailyRecapTime = dailyRecapTime;
  await savePrefs(prefs);

  const { lastRecapSentDate, ...publicPrefs } = prefs;
  res.json(publicPrefs);
});

// ── HEALTH CHECK ──────────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({
  status: 'ok',
  time: new Date().toISOString(),
  apnConfigured: apnProvider !== null,
  dbConnected: db !== null,
  stripeConfigured: stripe !== null,
}));

// ── START ─────────────────────────────────────────────────────────────────────
async function start() {
  if (!MONGODB_URI) {
    console.error('MONGODB_URI manquant — impossible de démarrer sans base de données.');
    process.exit(1);
  }

  mongoClient = new MongoClient(MONGODB_URI);
  await mongoClient.connect();
  db = mongoClient.db(MONGODB_DB_NAME);

  // Index utiles (idempotent : sans effet si déjà créés)
  await db.collection('bookings').createIndex({ id: 1 }, { unique: true });
  await db.collection('bookings').createIndex({ date: 1 });
  await db.collection('bookings').createIndex({ email: 1 });
  await db.collection('blocks').createIndex({ id: 1 }, { unique: true });
  await db.collection('clients').createIndex({ email: 1 }, { unique: true });
  await db.collection('devices').createIndex({ deviceToken: 1 }, { unique: true });
  await db.collection('giftCertificates').createIndex({ code: 1 }, { unique: true });
  await db.collection('giftCertificates').createIndex({ stripeSessionId: 1 }, { unique: true, sparse: true });

  console.log('Connecté à MongoDB.');

  setInterval(() => {
    checkDailyRecap().catch(e => console.error('Erreur récap quotidien :', e.message));
  }, 60 * 1000);

  app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT}`));
}

start().catch(e => {
  console.error('Échec du démarrage :', e.message);
  process.exit(1);
});
