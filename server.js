require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const apn = require('@parse/node-apn');

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
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
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

// ── DATA FILES ────────────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const BOOKINGS_FILE = path.join(DATA_DIR, 'bookings.json');
const BLOCKS_FILE = path.join(DATA_DIR, 'blocks.json');
const CLIENTS_FILE = path.join(DATA_DIR, 'clients.json');
const DEVICES_FILE = path.join(DATA_DIR, 'devices.json');
const PREFS_FILE = path.join(DATA_DIR, 'notification-prefs.json');

const DEFAULT_PREFS = { newBooking: true, dailyRecap: true, dailyRecapTime: '19:00', lastRecapSentDate: null };

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return []; }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

function readPrefs() {
  try { return { ...DEFAULT_PREFS, ...JSON.parse(fs.readFileSync(PREFS_FILE, 'utf8')) }; }
  catch { return { ...DEFAULT_PREFS }; }
}

function writePrefs(prefs) {
  writeJSON(PREFS_FILE, prefs);
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
let apnProvider = null;
if (process.env.APN_KEY_ID && process.env.APN_TEAM_ID && (process.env.APN_KEY || process.env.APN_KEY_PATH)) {
  try {
    apnProvider = new apn.Provider({
      token: {
        key: process.env.APN_KEY || process.env.APN_KEY_PATH,
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
  const devices = readJSON(DEVICES_FILE);
  if (!devices.length) return;

  const note = new apn.Notification();
  note.alert = { title, body };
  note.sound = 'default';
  note.topic = process.env.APN_BUNDLE_ID;

  const result = await apnProvider.send(note, devices.map(d => d.deviceToken));

  // Purge les tokens invalides (désinstallation, expiration…)
  const invalidTokens = new Set(
    result.failed
      .filter(f => ['BadDeviceToken', 'Unregistered'].includes(f.response?.reason))
      .map(f => f.device)
  );
  if (invalidTokens.size) {
    writeJSON(DEVICES_FILE, devices.filter(d => !invalidTokens.has(d.deviceToken)));
  }
}

// ── RÉCAP QUOTIDIEN ────────────────────────────────────────────────────────────
// Vérifie chaque minute si c'est l'heure d'envoyer le récap du lendemain.
// Nécessite que le fuseau du serveur Render corresponde à Europe/Paris
// (variable d'env TZ=Europe/Paris) pour que l'heure choisie soit correcte.
function checkDailyRecap() {
  const prefs = readPrefs();
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

  const bookings = readJSON(BOOKINGS_FILE)
    .filter(b => b.date === tomorrowStr && b.status !== 'cancelled')
    .sort((a, b) => a.startTime.localeCompare(b.startTime));

  prefs.lastRecapSentDate = today;
  writePrefs(prefs);

  if (!bookings.length) return;

  const list = bookings.map(b => `${b.startTime.replace(':00', 'h')} ${b.firstName} ${b.lastName[0]}.`).join(', ');
  sendPush(`Demain : ${bookings.length} RDV`, list).catch(e => console.error('Erreur envoi récap :', e.message));
}

setInterval(checkDailyRecap, 60 * 1000);

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

// GET /api/slots?date=YYYY-MM-DD&type=premiere|suivi
app.get('/api/slots', (req, res) => {
  const { date, type = 'suivi' } = req.query;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: 'Paramètre date invalide (YYYY-MM-DD)' });
  }
  const duration = SESSION_DURATIONS[type] || 60;
  const allSlots = generateDaySlots(date, duration);

  if (allSlots.length === 0) {
    return res.json({ date, slots: [] });
  }

  const bookings = readJSON(BOOKINGS_FILE).filter(b => b.date === date && b.status !== 'cancelled');
  const blocks   = readJSON(BLOCKS_FILE);

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

// POST /api/book
app.post('/api/book', (req, res) => {
  const { date, startTime, endTime, type, firstName, lastName, email, phone } = req.body;

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

  // Vérifier que le créneau est encore dispo (re-check côté serveur)
  const duration = SESSION_DURATIONS[type] || 60;
  const allSlots = generateDaySlots(date, duration);
  const slotExists = allSlots.some(s => s.start === startTime && s.end === endTime);
  if (!slotExists) {
    return res.status(409).json({ error: 'Ce créneau n\'est pas disponible pour ce type de séance' });
  }

  const bookings = readJSON(BOOKINGS_FILE);
  const blocks   = readJSON(BLOCKS_FILE);
  const dateObj  = new Date(date + 'T00:00:00');
  const dow      = dateObj.getDay();
  const reqStart = timeToMinutes(startTime);
  const reqEnd   = timeToMinutes(endTime);

  // Conflits réservations
  const conflict = bookings.some(b =>
    b.date === date &&
    b.status !== 'cancelled' &&
    reqStart < timeToMinutes(b.endTime) &&
    reqEnd   > timeToMinutes(b.startTime)
  );
  if (conflict) {
    return res.status(409).json({ error: 'Ce créneau vient d\'être réservé' });
  }

  // Conflits blocages
  for (const bl of blocks) {
    if (bl.type === 'day' && bl.date === date) {
      return res.status(409).json({ error: 'Cette journée est bloquée' });
    }
    if (bl.type === 'slot' && bl.date === date) {
      const bStart = timeToMinutes(bl.startTime);
      const bEnd   = timeToMinutes(bl.endTime);
      if (reqStart < bEnd && reqEnd > bStart) {
        return res.status(409).json({ error: 'Ce créneau est bloqué' });
      }
    }
    if (bl.type === 'recurring') {
      const recStart = new Date(bl.startDate + 'T00:00:00');
      const recEnd   = bl.endDate ? new Date(bl.endDate + 'T00:00:00') : null;
      if (dateObj >= recStart && (!recEnd || dateObj <= recEnd) && bl.dayOfWeek === dow) {
        const bStart = timeToMinutes(bl.startTime);
        const bEnd   = timeToMinutes(bl.endTime);
        if (reqStart < bEnd && reqEnd > bStart) {
          return res.status(409).json({ error: 'Ce créneau est bloqué' });
        }
      }
    }
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

  bookings.push(booking);
  writeJSON(BOOKINGS_FILE, bookings);

  res.status(201).json({
    success: true,
    bookingId: booking.id,
    message: 'Réservation confirmée',
  });

  const prefs = readPrefs();
  if (prefs.newBooking) {
    const typeLabel = { decouverte: 'Découverte', ado: 'Ado', kinesio: 'Kinésio', aromatouch: 'AromaTouch' }[type] || type;
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
app.get('/api/admin/bookings', requireAuth, (req, res) => {
  let bookings = readJSON(BOOKINGS_FILE);
  const { from, to, status } = req.query;
  if (from) bookings = bookings.filter(b => b.date >= from);
  if (to)   bookings = bookings.filter(b => b.date <= to);
  if (status) bookings = bookings.filter(b => b.status === status);
  bookings.sort((a, b) => a.date.localeCompare(b.date) || a.startTime.localeCompare(b.startTime));
  res.json(bookings);
});

// POST /api/admin/bookings/:id/cancel
app.post('/api/admin/bookings/:id/cancel', requireAuth, (req, res) => {
  const bookings = readJSON(BOOKINGS_FILE);
  const idx = bookings.findIndex(b => b.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Réservation introuvable' });
  bookings[idx].status = 'cancelled';
  bookings[idx].cancelledAt = new Date().toISOString();
  writeJSON(BOOKINGS_FILE, bookings);
  res.json({ success: true });
});

// GET /api/admin/blocks
app.get('/api/admin/blocks', requireAuth, (req, res) => {
  res.json(readJSON(BLOCKS_FILE));
});

// POST /api/admin/block
app.post('/api/admin/block', requireAuth, (req, res) => {
  const { type, date, startTime, endTime, startDate, endDate, dayOfWeek, reason } = req.body;

  if (!type || !['day', 'slot', 'recurring'].includes(type)) {
    return res.status(400).json({ error: 'Type invalide (day | slot | recurring)' });
  }

  const blocks = readJSON(BLOCKS_FILE);
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

  blocks.push(block);
  writeJSON(BLOCKS_FILE, blocks);
  res.status(201).json({ success: true, block });
});

// DELETE /api/admin/blocks/:id
app.delete('/api/admin/blocks/:id', requireAuth, (req, res) => {
  const blocks = readJSON(BLOCKS_FILE);
  const filtered = blocks.filter(b => b.id !== req.params.id);
  if (filtered.length === blocks.length) {
    return res.status(404).json({ error: 'Blocage introuvable' });
  }
  writeJSON(BLOCKS_FILE, filtered);
  res.json({ success: true });
});

// ── APPAREILS (notifications push) ─────────────────────────────────────────────

// POST /api/admin/device-token
app.post('/api/admin/device-token', requireAuth, (req, res) => {
  const { deviceToken, platform, label } = req.body;
  if (!deviceToken) return res.status(400).json({ error: 'deviceToken requis' });

  const devices = readJSON(DEVICES_FILE);
  const existing = devices.find(d => d.deviceToken === deviceToken);
  if (existing) {
    existing.label = label || existing.label;
    existing.platform = platform || existing.platform;
  } else {
    devices.push({ deviceToken, platform: platform || 'ios', label: label || '', registeredAt: new Date().toISOString() });
  }
  writeJSON(DEVICES_FILE, devices);
  res.status(201).json({ success: true });
});

// DELETE /api/admin/device-token/:token
app.delete('/api/admin/device-token/:token', requireAuth, (req, res) => {
  const devices = readJSON(DEVICES_FILE);
  const filtered = devices.filter(d => d.deviceToken !== req.params.token);
  writeJSON(DEVICES_FILE, filtered);
  res.json({ success: true });
});

// ── CLIENTS ────────────────────────────────────────────────────────────────────

// GET /api/admin/clients — liste agrégée depuis les réservations + notes
app.get('/api/admin/clients', requireAuth, (req, res) => {
  const bookings = readJSON(BOOKINGS_FILE);
  const clientsNotes = readJSON(CLIENTS_FILE);

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
    const note = clientsNotes.find(n => n.email === c.email);
    return { ...c, notes: note ? note.notes : '' };
  });

  clients.sort((a, b) => b.lastSessionDate.localeCompare(a.lastSessionDate));
  res.json(clients);
});

// GET /api/admin/clients/:email — fiche détaillée
app.get('/api/admin/clients/:email', requireAuth, (req, res) => {
  const email = req.params.email.toLowerCase();
  const bookings = readJSON(BOOKINGS_FILE)
    .filter(b => b.email === email)
    .sort((a, b) => b.date.localeCompare(a.date) || b.startTime.localeCompare(a.startTime));

  if (!bookings.length) return res.status(404).json({ error: 'Client introuvable' });

  const clientsNotes = readJSON(CLIENTS_FILE);
  const note = clientsNotes.find(n => n.email === email);
  const latest = bookings[0];

  res.json({
    email,
    firstName: latest.firstName,
    lastName: latest.lastName,
    phone: latest.phone,
    notes: note ? note.notes : '',
    bookings,
  });
});

// PUT /api/admin/clients/:email/notes
app.put('/api/admin/clients/:email/notes', requireAuth, (req, res) => {
  const email = req.params.email.toLowerCase();
  const { notes } = req.body;
  if (typeof notes !== 'string') return res.status(400).json({ error: 'notes requis (string)' });

  const clientsNotes = readJSON(CLIENTS_FILE);
  const existing = clientsNotes.find(n => n.email === email);
  if (existing) {
    existing.notes = notes;
    existing.updatedAt = new Date().toISOString();
  } else {
    clientsNotes.push({ email, notes, updatedAt: new Date().toISOString() });
  }
  writeJSON(CLIENTS_FILE, clientsNotes);
  res.json({ success: true });
});

// ── PRÉFÉRENCES DE NOTIFICATION ─────────────────────────────────────────────────

// GET /api/admin/notification-prefs
app.get('/api/admin/notification-prefs', requireAuth, (req, res) => {
  const { lastRecapSentDate, ...prefs } = readPrefs();
  res.json(prefs);
});

// PUT /api/admin/notification-prefs
app.put('/api/admin/notification-prefs', requireAuth, (req, res) => {
  const { newBooking, dailyRecap, dailyRecapTime } = req.body;

  if (dailyRecapTime !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(dailyRecapTime)) {
    return res.status(400).json({ error: 'dailyRecapTime invalide (format HH:MM)' });
  }

  const prefs = readPrefs();
  if (typeof newBooking === 'boolean') prefs.newBooking = newBooking;
  if (typeof dailyRecap === 'boolean') prefs.dailyRecap = dailyRecap;
  if (dailyRecapTime) prefs.dailyRecapTime = dailyRecapTime;
  writePrefs(prefs);

  const { lastRecapSentDate, ...publicPrefs } = prefs;
  res.json(publicPrefs);
});

// ── HEALTH CHECK ──────────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({
  status: 'ok',
  time: new Date().toISOString(),
  apnConfigured: apnProvider !== null,
}));

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT}`));
