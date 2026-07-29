require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const apn = require('@parse/node-apn');
const { MongoClient } = require('mongodb');
const Stripe = require('stripe');
const crypto = require('crypto');

const app = express();
// Derrière le proxy Render : nécessaire pour que express-rate-limit
// identifie la vraie IP client (X-Forwarded-For)
app.set('trust proxy', 1);
// Analyseur de query simple : l'analyseur étendu transforme `?status[$ne]=x` en
// objet imbriqué, qui se retrouverait tel quel dans un filtre MongoDB et y serait
// interprété comme un opérateur. Aucune route n'a besoin de query imbriquée.
app.set('query parser', 'simple');
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

// ── CORS ──────────────────────────────────────────────────────────────────────
// FRONTEND_URL accepte une ou plusieurs origines séparées par des virgules.
// Pour chacune, on autorise aussi la variante www/apex : l'hébergement sert le
// site sur les deux, et un visiteur arrivant sur « www. » voyait sinon toutes
// ses requêtes API échouer (créneaux, réservation, paiement) sans message clair.
function buildAllowedOrigins(raw) {
  const origins = new Set(['http://localhost:3000', 'http://127.0.0.1:5500']);
  for (const entry of String(raw || '').split(',')) {
    const value = entry.trim();
    if (!value || value === '*') continue;
    let url;
    try {
      url = new URL(value);
    } catch {
      console.error(`FRONTEND_URL : origine ignorée car illisible → « ${value} »`);
      continue;
    }
    const { protocol, host } = url;
    origins.add(`${protocol}//${host}`);
    origins.add(host.startsWith('www.')
      ? `${protocol}//${host.slice(4)}`
      : `${protocol}//www.${host}`);
  }
  return [...origins];
}

const ALLOWED_ORIGINS = buildAllowedOrigins(FRONTEND_URL);
if (!ALLOWED_ORIGINS.some(o => !o.includes('localhost') && !o.includes('127.0.0.1'))) {
  console.error('Aucune origine de production autorisée : vérifiez FRONTEND_URL. Le site en ligne ne pourra pas appeler l\'API.');
}
console.log('Origines CORS autorisées :', ALLOWED_ORIGINS.join(', '));

app.use(cors({
  origin: ALLOWED_ORIGINS,
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

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), wrap(async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(503).send('Stripe non configuré');

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook signature invalide : ${err.message}`);
  }

  // `completed` couvre le paiement carte immédiat ; `async_payment_succeeded`
  // couvre les moyens de paiement différés, dont la session se termine « unpaid »
  // et n'est confirmée que plus tard. Sans ce second cas, un paiement différé
  // encaissé ne créerait jamais de bon.
  const PAID_EVENTS = ['checkout.session.completed', 'checkout.session.async_payment_succeeded'];

  if (PAID_EVENTS.includes(event.type)) {
    const session = event.data.object;

    // Une session `completed` mais encore impayée sera confirmée par un
    // `async_payment_succeeded` ultérieur : ne rien créer maintenant.
    if (session.payment_status && session.payment_status === 'unpaid') {
      return res.json({ received: true, skipped: 'paiement en attente' });
    }

    try {
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

      // Idempotence : c'est l'index unique sur stripeSessionId qui fait foi, et
      // non une lecture préalable — Stripe peut rejouer le même événement, et
      // deux tentatives simultanées passeraient toutes deux un simple findOne.
      // Un doublon n'est pas une erreur : le bon existe déjà, on répond 200 pour
      // que Stripe cesse de rejouer l'événement.
      try {
        await db.collection('giftCertificates').insertOne(cert);
      } catch (e) {
        if (isDuplicateKey(e)) {
          return res.json({ received: true, duplicate: true });
        }
        throw e;
      }

      // Envoi de l'email en tâche de fond : Stripe abandonne le webhook au bout
      // de quelques secondes, et le bon est déjà enregistré — inutile de faire
      // attendre la réponse. `deliverGiftCertificate` consigne lui-même son
      // résultat et alerte en cas d'échec.
      deliverGiftCertificate(cert)
        .catch(e => console.error('Erreur de remise du bon cadeau :', e.message));
    } catch (e) {
      // 500 = Stripe rejouera l'événement, ce qui est le comportement voulu pour
      // une panne transitoire (base indisponible).
      console.error('Erreur traitement webhook Stripe :', e.message);
      return res.status(500).send('Erreur interne');
    }
  }

  res.json({ received: true });
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

// Paiement des bons cadeaux : 10 sessions Stripe par IP par heure.
// Route publique et non authentifiée : sans limite, un script peut créer des
// milliers de sessions (pollution du tableau de bord Stripe, quotas API).
app.use('/api/gift-certificates/checkout', rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Trop de tentatives de paiement, réessayez dans une heure.' },
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

// Source de vérité unique des tarifs : l'app iOS les récupère via GET /api/config
// au lieu de les redéclarer. Les modifier ici suffit — plus de risque de voir les
// statistiques calculées sur d'anciens prix sans que rien ne le signale.
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

// ── ÉTAT D'UNE SÉANCE (présence, encaissement, note de suivi) ─────────────────
//
// Principe : une séance passée est présumée **honorée et réglée au tarif
// habituel**. On ne stocke donc que les écarts à ce cas normal. Conséquence
// directe : les réservations déjà en base restent valides telles quelles et
// **aucune migration n'est nécessaire** — l'absence de champ `session` se lit
// comme « tout s'est passé normalement ».
//
// booking.session = {
//   note:       string,                               // suivi — donnée sensible, purgée avec le reste
//   attendance: 'attended' | 'noshow',                // absent → présumé honoré
//   payment:    'paid' | 'unpaid' | 'gift' | 'free',  // absent → présumé réglé
//   amount:     number,                               // absent → tarif du type de séance
//   method:     'cash' | 'card' | 'transfer' | 'check',
//   updatedAt:  string ISO,
// }
const ATTENDANCE_VALUES = ['attended', 'noshow'];
const PAYMENT_VALUES    = ['paid', 'unpaid', 'gift', 'free'];
const PAYMENT_METHODS   = ['cash', 'card', 'transfer', 'check'];

/// Ce qui compte réellement dans le chiffre d'affaires.
/// - `gift` est exclu volontairement : le bon cadeau a déjà été encaissé via
///   Stripe à l'achat. L'inclure ici compterait la même somme deux fois.
/// - `free` (séance offerte) et `unpaid` (pas encore réglée) sont exclus aussi,
///   mais restent visibles dans l'export pour pouvoir être relancés.
function sessionState(booking, today) {
  const s = booking.session || {};
  const cancelled = booking.status === 'cancelled';
  const isPast = booking.date < today;

  const attendance = s.attendance || (cancelled ? 'cancelled' : (isPast ? 'attended' : 'upcoming'));
  const payment = s.payment || (attendance === 'attended' ? 'paid' : 'none');
  const amount = typeof s.amount === 'number' ? s.amount : (SESSION_PRICES[booking.type] ?? 0);
  const counted = attendance === 'attended' && payment === 'paid';

  return {
    attendance,
    payment,
    amount,
    method: s.method || null,
    note: s.note || '',
    // Montant réellement acquis. Une séance non honorée, offerte, impayée ou
    // réglée par bon cadeau vaut 0 dans le chiffre d'affaires.
    revenue: counted ? amount : 0,
    isExplicit: Object.keys(s).length > 0,
  };
}

/// Échappement CSV : une cellule contenant `;`, un guillemet ou un saut de ligne
/// doit être encadrée de guillemets, les guillemets internes étant doublés.
/// Sans cela, un nom comme `Dupont; Marie` décalerait toute la ligne.
function csvCell(value) {
  const text = String(value ?? '');
  return /[";\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/// Joint l'état calculé à une réservation avant de l'envoyer à l'app.
/// L'app affiche `sessionState` sans rejouer la règle de présomption : une seule
/// implémentation, donc pas de divergence possible entre le chiffre du serveur
/// (export comptable) et celui affiché à l'écran.
function withSessionState(booking) {
  return { ...booking, sessionState: sessionState(booking, parisNow().day) };
}

/// Champs de dossier client. `contraindications` et `reason` sont des données de
/// santé : elles vivent dans la collection `clients`, que la purge RGPD supprime
/// intégralement — rien de plus à prévoir de ce côté.
function validateClientProfile(body) {
  for (const field of ['firstName', 'lastName', 'phone', 'reason', 'contraindications']) {
    const value = body[field];
    if (value === undefined || value === null) continue;
    if (typeof value !== 'string') return `${field} doit être une chaîne`;
    if (value.length > 2000) return `${field} trop long (2000 caractères maximum)`;
  }

  const { birthDate } = body;
  if (birthDate !== undefined && birthDate !== null && String(birthDate).trim() !== '') {
    if (typeof birthDate !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(birthDate)) {
      return 'birthDate doit être au format YYYY-MM-DD';
    }
    // `new Date('2026-02-31')` ne lève pas : il glisse au 3 mars. On recompare
    // donc la date reformatée pour rejeter un jour qui n'existe pas.
    const parsed = new Date(`${birthDate}T12:00:00Z`);
    if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== birthDate) {
      return 'birthDate n\'est pas une date valide';
    }
    if (birthDate > new Date().toISOString().slice(0, 10)) {
      return 'birthDate ne peut pas être dans le futur';
    }
    if (birthDate < '1900-01-01') return 'birthDate est trop ancienne';
  }
  return null;
}

function validateSessionPatch(body) {
  if (body.note !== undefined && typeof body.note !== 'string') {
    return 'note doit être une chaîne';
  }
  if (body.note !== undefined && body.note.length > 5000) {
    return 'note trop longue (5000 caractères maximum)';
  }
  if (body.attendance !== undefined && body.attendance !== null
      && !ATTENDANCE_VALUES.includes(body.attendance)) {
    return `attendance doit valoir ${ATTENDANCE_VALUES.join(' ou ')}`;
  }
  if (body.payment !== undefined && body.payment !== null
      && !PAYMENT_VALUES.includes(body.payment)) {
    return `payment doit valoir ${PAYMENT_VALUES.join(', ')}`;
  }
  if (body.method !== undefined && body.method !== null
      && !PAYMENT_METHODS.includes(body.method)) {
    return `method doit valoir ${PAYMENT_METHODS.join(', ')}`;
  }
  if (body.amount !== undefined && body.amount !== null
      && (typeof body.amount !== 'number' || !Number.isFinite(body.amount) || body.amount < 0)) {
    return 'amount doit être un nombre positif';
  }
  return null;
}

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

// ── REMISE DU BON CADEAU PAR EMAIL ────────────────────────────────────────────
// L'email part d'ici, et non du navigateur de l'acheteur comme auparavant :
// c'est le seul point du parcours dont l'exécution est garantie après un
// paiement réussi. Si l'acheteur ferme son onglet aussitôt payé, il reçoit
// quand même son code.
//
// Passe par l'API REST d'EmailJS, déjà utilisée par le site pour les
// confirmations de rendez-vous — pas de nouveau prestataire à gérer. Les appels
// hors navigateur exigent la clé privée ET l'option « API for non-browser
// applications » activée dans EmailJS (Account > Security).
const EMAILJS_SERVICE_ID = process.env.EMAILJS_SERVICE_ID;
const EMAILJS_PUBLIC_KEY = process.env.EMAILJS_PUBLIC_KEY;
const EMAILJS_PRIVATE_KEY = process.env.EMAILJS_PRIVATE_KEY;
const EMAILJS_TEMPLATE_GIFT = process.env.EMAILJS_TEMPLATE_GIFT || 'template_cadeau';
const emailConfigured = Boolean(EMAILJS_SERVICE_ID && EMAILJS_PUBLIC_KEY && EMAILJS_PRIVATE_KEY);

function formatFrenchDate(iso) {
  return new Intl.DateTimeFormat('fr-FR', {
    timeZone: PARIS_TZ, day: 'numeric', month: 'long', year: 'numeric',
  }).format(new Date(iso));
}

async function sendGiftEmail(cert) {
  if (!emailConfigured) {
    throw new Error('EmailJS non configuré (EMAILJS_SERVICE_ID / EMAILJS_PUBLIC_KEY / EMAILJS_PRIVATE_KEY manquants)');
  }
  if (!cert.purchaserEmail) {
    throw new Error('Aucune adresse email pour cet acheteur');
  }

  // Sans délai maximal, un prestataire qui ne répond pas laisserait la promesse
  // en suspens indéfiniment et le statut ne serait jamais consigné.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        service_id: EMAILJS_SERVICE_ID,
        template_id: EMAILJS_TEMPLATE_GIFT,
        user_id: EMAILJS_PUBLIC_KEY,
        accessToken: EMAILJS_PRIVATE_KEY,
        template_params: {
          to_email:        cert.purchaserEmail,
          to_name:         cert.purchaserName || '',
          code:            cert.code,
          type_seance:     TYPE_LABELS[cert.type] || cert.type,
          montant:         `${cert.amount} €`,
          recipient_name:  cert.recipientName || cert.purchaserName || '',
          message:         cert.message || '',
          date_expiration: formatFrenchDate(cert.expiresAt),
        },
      }),
    });

    if (!response.ok) {
      const detail = (await response.text().catch(() => '')).slice(0, 200);
      throw new Error(`EmailJS a répondu ${response.status}${detail ? ` — ${detail}` : ''}`);
    }
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('EmailJS n\'a pas répondu dans les 15 secondes');
    throw e;
  } finally {
    clearTimeout(timeout);
  }
}

/// Envoie le bon, consigne le résultat sur le document, et prévient Mathilde.
///
/// Un échec ne doit jamais rester silencieux : le client a payé. On enregistre
/// donc l'erreur sur le bon (l'app affiche l'état et propose de réessayer) et on
/// pousse une notification contenant le code, pour qu'elle puisse le transmettre
/// à la main dans l'intervalle.
async function deliverGiftCertificate(cert) {
  try {
    await sendGiftEmail(cert);
    await db.collection('giftCertificates').updateOne(
      { code: cert.code },
      { $set: { emailSentAt: new Date().toISOString() }, $unset: { emailError: '' } }
    );
    sendPush(
      'Bon cadeau vendu 🎁',
      `${TYPE_LABELS[cert.type] || cert.type} — ${cert.amount} € pour ${cert.recipientName || cert.purchaserName}`
    ).catch(e => console.error('Erreur envoi push bon cadeau :', e.message));
    return true;
  } catch (e) {
    console.error(`Envoi du bon cadeau ${cert.code} à ${cert.purchaserEmail} en échec :`, e.message);
    await db.collection('giftCertificates').updateOne(
      { code: cert.code },
      { $set: { emailError: e.message, emailErrorAt: new Date().toISOString() } }
    ).catch(err => console.error('Impossible de consigner l\'échec d\'envoi :', err.message));
    sendPush(
      '⚠️ Bon cadeau à envoyer à la main',
      `${cert.code} — ${cert.purchaserEmail} n'a PAS reçu son email. Ouvre l'app pour réessayer.`
    ).catch(err => console.error('Erreur envoi push échec email :', err.message));
    return false;
  }
}

// ── RÉCAP QUOTIDIEN ────────────────────────────────────────────────────────────
// Tout est calculé dans le fuseau d'Itteville, quel que soit celui du serveur.
// L'ancienne version mélangeait l'heure locale (getHours) et la date UTC
// (toISOString) : à 19 h l'écart ne se voyait pas, mais pour une heure de récap
// située entre minuit et 02 h, les deux ne désignaient plus le même jour et le
// garde-fou « déjà envoyé aujourd'hui » sautait.
const PARIS_TZ = 'Europe/Paris';
const parisFormatter = new Intl.DateTimeFormat('fr-FR', {
  timeZone: PARIS_TZ,
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
});

/// Date et heure murales à Paris, au format { day: 'YYYY-MM-DD', time: 'HH:MM' }.
function parisNow(date = new Date()) {
  const parts = Object.fromEntries(
    parisFormatter.formatToParts(date).map(p => [p.type, p.value])
  );
  return {
    day: `${parts.year}-${parts.month}-${parts.day}`,
    time: `${parts.hour}:${parts.minute}`,
  };
}

/// Jour calendaire suivant. Le calcul passe par midi UTC pour rester à l'abri
/// des changements d'heure, qui peuvent faire durer un jour 23 ou 25 heures.
function nextDay(dayStr) {
  const d = new Date(`${dayStr}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

async function checkDailyRecap() {
  const prefs = await getPrefs();
  if (!prefs.dailyRecap) return;

  const { day: today, time: currentTime } = parisNow();

  if (currentTime !== prefs.dailyRecapTime || prefs.lastRecapSentDate === today) return;

  const tomorrowStr = nextDay(today);

  const bookings = (await db.collection('bookings')
    .find({ date: tomorrowStr, status: { $ne: 'cancelled' } }, NO_ID_PROJECTION)
    .toArray())
    .sort((a, b) => a.startTime.localeCompare(b.startTime));

  await savePrefs({ ...prefs, lastRecapSentDate: today });

  if (!bookings.length) return;

  const list = bookings.map(b => `${b.startTime.replace(':00', 'h')} ${b.firstName} ${b.lastName[0]}.`).join(', ');
  sendPush(`Demain : ${bookings.length} RDV`, list).catch(e => console.error('Erreur envoi récap :', e.message));
}

// ── GESTION DES ERREURS ───────────────────────────────────────────────────────
// Express 4 n'intercepte pas les rejets de promesses : une exception dans un
// handler `async` (erreur Mongo transitoire, champ d'un type inattendu…) part
// en « unhandled rejection », que Node traite par défaut en arrêtant le
// processus. On enveloppe donc chaque route async pour renvoyer l'erreur au
// middleware ci-dessous plutôt que de faire tomber le serveur.
// Déclaration de fonction (et non `const`) : elle est hoistée, donc utilisable
// par les routes déclarées plus haut dans le fichier, comme le webhook Stripe.
function wrap(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

// Violation d'index unique MongoDB (code 11000) : deux écritures concurrentes
// ont visé la même clé. C'est le filet qui empêche la double réservation d'un
// créneau, la vérification de disponibilité seule n'étant pas atomique.
function isDuplicateKey(err) {
  return err && (err.code === 11000 || err.code === 11001);
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

// Valide la forme d'un blocage. Un blocage mal formé serait ensuite relu par
// timeToMinutes() dans /api/slots — route publique — et la ferait échouer pour
// tous les visiteurs.
function validateBlockShape({ type, date, startTime, endTime, startDate, endDate, dayOfWeek } = {}) {
  if (!type || !['day', 'slot', 'recurring'].includes(type)) {
    return 'Type invalide (day | slot | recurring)';
  }
  if (type === 'day') {
    if (!DATE_RE.test(date)) return 'Date requise (YYYY-MM-DD)';
  } else if (type === 'slot') {
    if (!DATE_RE.test(date)) return 'Date requise (YYYY-MM-DD)';
    if (!TIME_RE.test(startTime) || !TIME_RE.test(endTime)) return 'Horaires requis (HH:MM)';
    if (startTime >= endTime) return 'L\'heure de fin doit suivre l\'heure de début';
  } else {
    if (!DATE_RE.test(startDate)) return 'startDate requise (YYYY-MM-DD)';
    if (endDate && !DATE_RE.test(endDate)) return 'endDate invalide (YYYY-MM-DD)';
    if (!TIME_RE.test(startTime) || !TIME_RE.test(endTime)) return 'Horaires requis (HH:MM)';
    if (startTime >= endTime) return 'L\'heure de fin doit suivre l\'heure de début';
    if (!Number.isInteger(Number(dayOfWeek)) || Number(dayOfWeek) < 0 || Number(dayOfWeek) > 6) {
      return 'dayOfWeek invalide (0-6)';
    }
  }
  return null;
}

// Normalise un paramètre de query en chaîne simple avant de le placer dans un
// filtre MongoDB. Deuxième garde-fou après `query parser: simple` : même une
// clé répétée (`?status=a&status=b`, qui donne un tableau) devient une chaîne
// inoffensive plutôt qu'un opérateur.
function queryString(value) {
  if (value === undefined || value === null) return undefined;
  const str = String(value).trim();
  return str === '' ? undefined : str;
}

// Valide qu'un champ est bien une chaîne non vide. Sans ce contrôle, un corps
// JSON du type {"firstName": {}} passe la vérification de présence puis lève une
// TypeError sur .trim().
function requireStrings(body, fields) {
  for (const field of fields) {
    const value = body?.[field];
    if (typeof value !== 'string' || !value.trim()) {
      return `Champ « ${field} » manquant ou invalide`;
    }
  }
  return null;
}

// Comparaison à durée constante : `===` s'arrête au premier caractère différent,
// ce qui fait très légèrement varier le temps de réponse selon le nombre de
// caractères corrects. La limite de débit (5 essais / 15 min) rend l'attaque
// irréaliste ici ; on corrige par principe, un mot de passe ne se compare pas
// avec un opérateur d'égalité classique.
function passwordMatches(candidate) {
  const a = Buffer.from(candidate, 'utf8');
  const b = Buffer.from(ADMIN_PASSWORD, 'utf8');
  // timingSafeEqual exige des longueurs identiques : on hache d'abord pour
  // obtenir deux tampons de même taille, sinon la longueur elle-même fuirait.
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ── CONSERVATION DES DONNÉES (RGPD) ───────────────────────────────────────────
// La politique de confidentialité publiée annonce : « archivées pendant une
// période maximale de 3 ans à compter du dernier contact. Au-delà, elles sont
// supprimées ou anonymisées. » Cet engagement est public ; il doit donc être
// tenu automatiquement, sans dépendre d'un ménage manuel.
//
// Anonymisation plutôt que suppression : l'historique reste exploitable pour la
// comptabilité et les statistiques, sans plus permettre d'identifier personne.
// Désactivable avec DATA_RETENTION_ENABLED=false ; durée ajustable avec
// DATA_RETENTION_YEARS.
const RETENTION_YEARS = Number(process.env.DATA_RETENTION_YEARS || 3);
const RETENTION_ENABLED = process.env.DATA_RETENTION_ENABLED !== 'false';

async function purgeExpiredPersonalData() {
  if (!RETENTION_ENABLED) return;

  const cutoff = new Date();
  cutoff.setFullYear(cutoff.getFullYear() - RETENTION_YEARS);
  const cutoffDay = cutoff.toISOString().slice(0, 10);

  // Les RDV déjà anonymisés ne contiennent plus de données personnelles :
  // les exclure évite de les retraiter chaque jour.
  const expired = await db.collection('bookings')
    .find({ date: { $lt: cutoffDay }, anonymisedAt: { $exists: false } }, NO_ID_PROJECTION)
    .toArray();
  if (!expired.length) return;

  const emails = [...new Set(expired.map(b => b.email))];

  // Un client encore actif ne doit pas être anonymisé pour ses vieilles séances :
  // le délai court à partir du DERNIER contact, pas de la date de chaque RDV.
  const stillActive = new Set(
    (await db.collection('bookings')
      .find({ email: { $in: emails }, date: { $gte: cutoffDay } }, NO_ID_PROJECTION)
      .toArray())
      .map(b => b.email)
  );

  const toAnonymise = emails.filter(e => !stillActive.has(e));
  if (!toAnonymise.length) return;

  let count = 0;
  for (const email of toAnonymise) {
    await db.collection('clients').deleteOne({ email });
    const result = await db.collection('bookings').updateMany(
      { email },
      {
        $set: {
          firstName: 'Anonyme',
          lastName: '',
          email: `anonymise-${uuidv4()}@invalide.local`,
          phone: '',
          anonymisedAt: new Date().toISOString(),
        },
        // La note de suivi est la donnée la plus sensible du dossier : elle doit
        // disparaître, pas survivre à l'anonymisation de l'identité. Les données
        // comptables (montant, règlement) sont conservées — elles n'identifient
        // personne et l'obligation de conservation comptable est plus longue.
        $unset: { 'session.note': '' },
      }
    );
    count += result.modifiedCount;
  }

  console.log(
    `Conservation des données : ${toAnonymise.length} client(s) sans contact depuis ` +
    `plus de ${RETENTION_YEARS} ans — fiche supprimée, ${count} RDV anonymisés.`
  );
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
app.get('/api/slots', wrap(async (req, res) => {
  const date      = queryString(req.query.date);
  const type      = queryString(req.query.type) || 'suivi';
  const excludeId = queryString(req.query.excludeId);

  if (!date || !DATE_RE.test(date)) {
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
}));

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
app.post('/api/book', wrap(async (req, res) => {
  const { date, startTime, endTime, type, firstName, lastName, email, phone, giftCode } = req.body;

  // Validation basique
  const typeError = requireStrings(req.body, ['date', 'startTime', 'endTime', 'type', 'firstName', 'lastName', 'email', 'phone']);
  if (typeError) {
    return res.status(400).json({ error: typeError });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: 'Date invalide' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Email invalide' });
  }
  if (giftCode !== undefined && giftCode !== null && typeof giftCode !== 'string') {
    return res.status(400).json({ error: 'Code cadeau invalide' });
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

  try {
    await db.collection('bookings').insertOne(booking);
  } catch (e) {
    if (isDuplicateKey(e)) return res.status(409).json({ error: 'Ce créneau vient d\'être réservé' });
    throw e;
  }
  delete booking._id;

  // Consommation atomique du bon : le filtre `status != redeemed` garantit
  // qu'une seule réservation peut l'utiliser, même en cas d'envois simultanés.
  if (giftCert) {
    const redeemed = await db.collection('giftCertificates').updateOne(
      { code: giftCert, status: { $ne: 'redeemed' } },
      { $set: { status: 'redeemed', redeemedAt: new Date().toISOString(), redeemedBookingId: booking.id } }
    );
    if (redeemed.modifiedCount === 0) {
      // Le bon a été consommé entre la validation et ici : on annule la
      // réservation pour ne pas offrir une séance qui n'a pas été payée.
      await db.collection('bookings').deleteOne({ id: booking.id });
      return res.status(409).json({ error: 'Ce bon cadeau vient d\'être utilisé' });
    }
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
}));

// ── ROUTES ADMIN ──────────────────────────────────────────────────────────────

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (typeof password !== 'string' || !passwordMatches(password)) {
    return res.status(401).json({ error: 'Mot de passe incorrect' });
  }
  // 30 jours : usage quotidien depuis l'app mobile en plus du web
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

// GET /api/admin/bookings?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/api/admin/bookings', requireAuth, wrap(async (req, res) => {
  const from   = queryString(req.query.from);
  const to     = queryString(req.query.to);
  const status = queryString(req.query.status);

  const filter = {};
  if (from || to) {
    filter.date = {};
    if (from) filter.date.$gte = from;
    if (to)   filter.date.$lte = to;
  }
  if (status) filter.status = status;

  const bookings = await db.collection('bookings').find(filter, NO_ID_PROJECTION).toArray();
  bookings.sort((a, b) => a.date.localeCompare(b.date) || a.startTime.localeCompare(b.startTime));
  res.json(bookings.map(withSessionState));
}));

// POST /api/admin/bookings — création manuelle par Mathilde depuis l'app.
// Distincte de /api/book (publique) : pas de limite de débit, et pas de
// notification push (inutile de s'auto-alerter d'un RDV qu'on vient de saisir).
app.post('/api/admin/bookings', requireAuth, wrap(async (req, res) => {
  const { date, startTime, endTime, type, firstName, lastName, email, phone } = req.body;

  const typeError = requireStrings(req.body, ['date', 'startTime', 'endTime', 'type', 'firstName', 'lastName', 'email', 'phone']);
  if (typeError) {
    return res.status(400).json({ error: typeError });
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

  try {
    await db.collection('bookings').insertOne(booking);
  } catch (e) {
    if (isDuplicateKey(e)) return res.status(409).json({ error: 'Ce créneau vient d\'être réservé' });
    throw e;
  }
  delete booking._id;
  res.status(201).json({ success: true, bookingId: booking.id });
}));

// POST /api/admin/bookings/:id/cancel
app.post('/api/admin/bookings/:id/cancel', requireAuth, wrap(async (req, res) => {
  const result = await db.collection('bookings').updateOne(
    { id: req.params.id },
    { $set: { status: 'cancelled', cancelledAt: new Date().toISOString() } }
  );
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Réservation introuvable' });
  res.json({ success: true });
}));

// PUT /api/admin/bookings/:id/session — note de suivi, présence, encaissement
//
// Écriture partielle : seuls les champs présents dans le corps sont modifiés.
// Envoyer `null` sur `attendance` ou `payment` efface l'exception et fait
// retomber la séance dans le cas présumé (honorée / réglée).
app.put('/api/admin/bookings/:id/session', requireAuth, wrap(async (req, res) => {
  const shapeError = validateSessionPatch(req.body || {});
  if (shapeError) return res.status(400).json({ error: shapeError });

  const existing = await db.collection('bookings').findOne({ id: req.params.id }, NO_ID_PROJECTION);
  if (!existing) return res.status(404).json({ error: 'Réservation introuvable' });

  const session = { ...(existing.session || {}) };
  for (const field of ['note', 'attendance', 'payment', 'method', 'amount']) {
    if (!(field in req.body)) continue;
    const value = req.body[field];
    // `null` ou chaîne vide = revenir au comportement par défaut, sans laisser
    // traîner une clé vide qui ferait passer la séance pour « renseignée ».
    if (value === null || value === '') delete session[field];
    else session[field] = value;
  }

  const update = Object.keys(session).length
    ? { $set: { session: { ...session, updatedAt: new Date().toISOString() } } }
    : { $unset: { session: '' } };

  await db.collection('bookings').updateOne({ id: req.params.id }, update);

  const updated = await db.collection('bookings').findOne({ id: req.params.id }, NO_ID_PROJECTION);
  res.json({ success: true, session: sessionState(updated, parisNow().day) });
}));

// GET /api/admin/export?from=&to= — export comptable au format CSV
app.get('/api/admin/export', requireAuth, wrap(async (req, res) => {
  const from = queryString(req.query.from);
  const to   = queryString(req.query.to);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(from) || !/^\d{4}-\d{2}-\d{2}$/.test(to)) {
    return res.status(400).json({ error: 'Paramètres from et to requis au format YYYY-MM-DD' });
  }

  const bookings = (await db.collection('bookings')
    .find({ date: { $gte: from, $lte: to } }, NO_ID_PROJECTION)
    .toArray())
    .sort((a, b) => a.date.localeCompare(b.date) || a.startTime.localeCompare(b.startTime));

  const today = parisNow().day;
  const rows = [['Date', 'Heure', 'Client', 'Prestation', 'Statut', 'Règlement', 'Moyen', 'Montant encaissé']];

  for (const b of bookings) {
    const state = sessionState(b, today);
    if (state.attendance === 'upcoming') continue; // pas encore eu lieu : hors comptabilité
    rows.push([
      b.date,
      b.startTime,
      `${b.firstName} ${b.lastName}`.trim(),
      TYPE_LABELS[b.type] || b.type,
      { attended: 'Honorée', noshow: 'Absence', cancelled: 'Annulée' }[state.attendance] || state.attendance,
      { paid: 'Réglée', unpaid: 'En attente', gift: 'Bon cadeau', free: 'Offerte', none: '' }[state.payment] || '',
      { cash: 'Espèces', card: 'Carte', transfer: 'Virement', check: 'Chèque' }[state.method] || '',
      state.revenue.toFixed(2).replace('.', ','), // séparateur décimal français, pour Excel/Numbers en FR
    ]);
  }

  const total = bookings.reduce((sum, b) => sum + sessionState(b, today).revenue, 0);
  rows.push([]);
  rows.push(['', '', '', '', '', '', 'Total encaissé', total.toFixed(2).replace('.', ',')]);

  // Point-virgule : séparateur attendu par Excel en locale française.
  // BOM UTF-8 : sans lui, Excel affiche « SÃ©ance » au lieu de « Séance ».
  const csv = '\uFEFF' + rows.map(row => row.map(csvCell).join(';')).join('\r\n');

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="seances-${from}_${to}.csv"`);
  res.send(csv);
}));

// PUT /api/admin/bookings/:id — reprogrammer / corriger une réservation
app.put('/api/admin/bookings/:id', requireAuth, wrap(async (req, res) => {
  const existing = await db.collection('bookings').findOne({ id: req.params.id }, NO_ID_PROJECTION);
  if (!existing) return res.status(404).json({ error: 'Réservation introuvable' });

  const { date, startTime, endTime, type, firstName, lastName, email, phone } = req.body;

  const typeError = requireStrings(req.body, ['date', 'startTime', 'endTime', 'type', 'firstName', 'lastName', 'email', 'phone']);
  if (typeError) {
    return res.status(400).json({ error: typeError });
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

  try {
    await db.collection('bookings').updateOne({ id: req.params.id }, { $set: updated });
  } catch (e) {
    if (isDuplicateKey(e)) return res.status(409).json({ error: 'Ce créneau vient d\'être réservé' });
    throw e;
  }
  res.json({ success: true, booking: { ...existing, ...updated } });
}));

// GET /api/admin/blocks
app.get('/api/admin/blocks', requireAuth, wrap(async (req, res) => {
  res.json(await db.collection('blocks').find({}, NO_ID_PROJECTION).toArray());
}));

// POST /api/admin/block
app.post('/api/admin/block', requireAuth, wrap(async (req, res) => {
  const { type, date, startTime, endTime, startDate, endDate, dayOfWeek, reason } = req.body;

  const shapeError = validateBlockShape(req.body);
  if (shapeError) return res.status(400).json({ error: shapeError });

  const block = { id: uuidv4(), type, reason: typeof reason === 'string' ? reason : '', createdAt: new Date().toISOString() };

  if (type === 'day') {
    block.date = date;
  } else if (type === 'slot') {
    block.date = date;
    block.startTime = startTime;
    block.endTime   = endTime;
  } else if (type === 'recurring') {
    block.startDate  = startDate;
    block.endDate    = endDate || null;
    block.startTime  = startTime;
    block.endTime    = endTime;
    block.dayOfWeek  = Number(dayOfWeek);
  }

  await db.collection('blocks').insertOne(block);
  delete block._id;
  res.status(201).json({ success: true, block });
}));

// PUT /api/admin/blocks/:id — modifier un blocage existant
app.put('/api/admin/blocks/:id', requireAuth, wrap(async (req, res) => {
  const existing = await db.collection('blocks').findOne({ id: req.params.id }, NO_ID_PROJECTION);
  if (!existing) return res.status(404).json({ error: 'Blocage introuvable' });

  const { type, date, startTime, endTime, startDate, endDate, dayOfWeek, reason } = req.body;

  const shapeError = validateBlockShape(req.body);
  if (shapeError) return res.status(400).json({ error: shapeError });

  const updated = { type, reason: typeof reason === 'string' ? reason : '' };

  if (type === 'day') {
    updated.date = date;
  } else if (type === 'slot') {
    updated.date = date;
    updated.startTime = startTime;
    updated.endTime = endTime;
  } else if (type === 'recurring') {
    updated.startDate = startDate;
    updated.endDate = endDate || null;
    updated.startTime = startTime;
    updated.endTime = endTime;
    updated.dayOfWeek = Number(dayOfWeek);
  }

  await db.collection('blocks').replaceOne({ id: req.params.id }, { id: existing.id, ...updated, createdAt: existing.createdAt });
  res.json({ success: true, block: { id: existing.id, ...updated, createdAt: existing.createdAt } });
}));

// DELETE /api/admin/blocks/:id
app.delete('/api/admin/blocks/:id', requireAuth, wrap(async (req, res) => {
  const result = await db.collection('blocks').deleteOne({ id: req.params.id });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Blocage introuvable' });
  res.json({ success: true });
}));

// ── APPAREILS (notifications push) ─────────────────────────────────────────────

// POST /api/admin/device-token
app.post('/api/admin/device-token', requireAuth, wrap(async (req, res) => {
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
}));

// DELETE /api/admin/device-token/:token
app.delete('/api/admin/device-token/:token', requireAuth, wrap(async (req, res) => {
  await db.collection('devices').deleteOne({ deviceToken: req.params.token });
  res.json({ success: true });
}));

// ── BONS CADEAUX ──────────────────────────────────────────────────────────────

// POST /api/gift-certificates/checkout — crée une session de paiement Stripe
app.post('/api/gift-certificates/checkout', wrap(async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Paiement en ligne indisponible pour le moment' });

  const { recipientName, message, purchaserName, purchaserEmail } = req.body;
  // Les bons cadeaux ne sont proposés que pour le soin AromaTouch® pour le moment.
  const type = 'aromatouch';
  const typeError = requireStrings(req.body, ['purchaserName', 'purchaserEmail']);
  if (typeError) {
    return res.status(400).json({ error: typeError });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(purchaserEmail)) {
    return res.status(400).json({ error: 'Email invalide' });
  }
  // Champs facultatifs : ils finissent dans les métadonnées Stripe via .slice(),
  // qui échouerait sur autre chose qu'une chaîne.
  for (const [name, value] of [['recipientName', recipientName], ['message', message]]) {
    if (value !== undefined && value !== null && typeof value !== 'string') {
      return res.status(400).json({ error: `Champ « ${name} » invalide` });
    }
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
}));

// GET /api/gift-certificates/session/:sessionId — la page de succès l'interroge
// pour afficher le code une fois le webhook traité (peut arriver quelques
// secondes après la redirection).
// Route publique : l'identifiant de session Stripe circule dans l'URL, donc dans
// l'historique du navigateur et l'en-tête Referer. On ne renvoie que ce qui est
// nécessaire à l'affichage du bon — jamais l'email de l'acheteur ni le message
// personnel, qui n'ont pas à sortir d'ici.
app.get('/api/gift-certificates/session/:sessionId', wrap(async (req, res) => {
  const cert = await db.collection('giftCertificates').findOne(
    { stripeSessionId: String(req.params.sessionId) },
    { projection: { _id: 0, code: 1, type: 1, amount: 1, expiresAt: 1, recipientName: 1 } }
  );
  if (!cert) return res.status(404).json({ error: 'pending' });
  res.json(cert);
}));

// GET /api/admin/gift-certificates
app.get('/api/admin/gift-certificates', requireAuth, wrap(async (req, res) => {
  const certs = await db.collection('giftCertificates').find({}, NO_ID_PROJECTION).toArray();
  certs.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json(certs);
}));

// POST /api/admin/gift-certificates/:code/resend-email — renvoi manuel depuis l'app,
// après un échec d'envoi ou à la demande de l'acheteur (email perdu, adresse
// mal saisie…).
app.post('/api/admin/gift-certificates/:code/resend-email', requireAuth, wrap(async (req, res) => {
  const code = String(req.params.code).trim().toUpperCase();
  const cert = await db.collection('giftCertificates').findOne({ code }, NO_ID_PROJECTION);
  if (!cert) return res.status(404).json({ error: 'Bon cadeau introuvable' });

  // Permet de corriger une adresse erronée au passage.
  const { email } = req.body || {};
  if (email !== undefined) {
    if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Email invalide' });
    }
    await db.collection('giftCertificates').updateOne({ code }, { $set: { purchaserEmail: email.trim().toLowerCase() } });
    cert.purchaserEmail = email.trim().toLowerCase();
  }

  try {
    await sendGiftEmail(cert);
  } catch (e) {
    await db.collection('giftCertificates').updateOne(
      { code },
      { $set: { emailError: e.message, emailErrorAt: new Date().toISOString() } }
    );
    return res.status(502).json({ error: `Envoi impossible : ${e.message}` });
  }

  await db.collection('giftCertificates').updateOne(
    { code },
    { $set: { emailSentAt: new Date().toISOString() }, $unset: { emailError: '' } }
  );
  res.json({ success: true, sentTo: cert.purchaserEmail });
}));

// POST /api/admin/gift-certificates/:code/redeem — usage manuel (code présenté en personne)
app.post('/api/admin/gift-certificates/:code/redeem', requireAuth, wrap(async (req, res) => {
  const code = req.params.code.trim().toUpperCase();
  const cert = await db.collection('giftCertificates').findOne({ code });
  if (!cert) return res.status(404).json({ error: 'Bon cadeau introuvable' });
  if (cert.status === 'redeemed') return res.status(409).json({ error: 'Ce bon cadeau a déjà été utilisé' });

  await db.collection('giftCertificates').updateOne(
    { code },
    { $set: { status: 'redeemed', redeemedAt: new Date().toISOString() } }
  );
  res.json({ success: true });
}));

// ── CLIENTS ────────────────────────────────────────────────────────────────────

// GET /api/admin/clients — liste agrégée depuis les réservations + notes
app.get('/api/admin/clients', requireAuth, wrap(async (req, res) => {
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
}));

// GET /api/admin/clients/:email — fiche détaillée
app.get('/api/admin/clients/:email', requireAuth, wrap(async (req, res) => {
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
    birthDate: profile?.birthDate || '',
    reason: profile?.reason || '',
    contraindications: profile?.contraindications || '',
    bookings: bookings.map(withSessionState),
  });
}));

// PUT /api/admin/clients/:email/profile — identité et éléments de dossier
app.put('/api/admin/clients/:email/profile', requireAuth, wrap(async (req, res) => {
  const email = req.params.email.toLowerCase();
  const { firstName, lastName, phone, birthDate, reason, contraindications } = req.body;

  const shapeError = validateClientProfile(req.body || {});
  if (shapeError) return res.status(400).json({ error: shapeError });

  const update = { updatedAt: new Date().toISOString() };
  const unset = {};

  // Identité : jamais effacée par mégarde — une chaîne vide est ignorée, car
  // ces champs ont toujours une valeur de repli issue de la réservation.
  if (typeof firstName === 'string' && firstName.trim()) update.firstName = firstName.trim();
  if (typeof lastName === 'string' && lastName.trim())   update.lastName  = lastName.trim();
  if (typeof phone === 'string' && phone.trim())         update.phone    = phone.trim();

  // Éléments de dossier : eux doivent pouvoir être effacés. Une contre-indication
  // saisie par erreur et impossible à retirer serait pire que pas de champ du tout.
  for (const [field, value] of Object.entries({ birthDate, reason, contraindications })) {
    if (value === undefined) continue;
    if (value === null || String(value).trim() === '') unset[field] = '';
    else update[field] = String(value).trim();
  }

  const operations = { $set: update, $setOnInsert: { email } };
  if (Object.keys(unset).length) operations.$unset = unset;

  await db.collection('clients').updateOne({ email }, operations, { upsert: true });
  res.json({ success: true });
}));

// PUT /api/admin/clients/:email/notes
app.put('/api/admin/clients/:email/notes', requireAuth, wrap(async (req, res) => {
  const email = req.params.email.toLowerCase();
  const { notes } = req.body;
  if (typeof notes !== 'string') return res.status(400).json({ error: 'notes requis (string)' });

  await db.collection('clients').updateOne(
    { email },
    { $set: { notes, updatedAt: new Date().toISOString() }, $setOnInsert: { email } },
    { upsert: true }
  );
  res.json({ success: true });
}));

// DELETE /api/admin/clients/:email — droit à l'effacement (RGPD, art. 17)
//
// Deux natures de données, deux traitements :
//   • la fiche client (nom, téléphone, notes de séance) est SUPPRIMÉE — ce sont
//     les données les plus sensibles, sans obligation de conservation ;
//   • l'historique des rendez-vous est ANONYMISÉ plutôt que supprimé, pour ne
//     pas trouer la comptabilité (les justificatifs de recettes se conservent).
//     Il ne reste alors que la date, l'horaire et le type de séance.
//
// `?purge=true` supprime aussi les rendez-vous, pour les cas où aucune
// obligation comptable ne s'applique.
app.delete('/api/admin/clients/:email', requireAuth, wrap(async (req, res) => {
  const email = req.params.email.toLowerCase();
  const purge = queryString(req.query.purge) === 'true';

  const bookings = await db.collection('bookings').find({ email }, NO_ID_PROJECTION).toArray();
  const profile = await db.collection('clients').findOne({ email });
  if (!bookings.length && !profile) {
    return res.status(404).json({ error: 'Client introuvable' });
  }

  await db.collection('clients').deleteOne({ email });

  let anonymised = 0;
  let deleted = 0;
  if (purge) {
    deleted = (await db.collection('bookings').deleteMany({ email })).deletedCount;
  } else {
    anonymised = (await db.collection('bookings').updateMany(
      { email },
      {
        $set: {
          firstName: 'Anonyme',
          lastName: '',
          // L'email sert de clé de regroupement : on le remplace par une valeur
          // unique et non réversible plutôt que de le vider, sinon toutes les
          // fiches anonymisées fusionneraient en un seul « client ».
          email: `anonymise-${uuidv4()}@invalide.local`,
          phone: '',
          anonymisedAt: new Date().toISOString(),
        },
        // Idem purge automatique : la note de suivi part avec l'identité.
        $unset: { 'session.note': '' },
      }
    )).modifiedCount;
  }

  console.log(`RGPD : effacement demandé pour un client — ${anonymised} RDV anonymisés, ${deleted} supprimés.`);
  res.json({ success: true, profileDeleted: !!profile, bookingsAnonymised: anonymised, bookingsDeleted: deleted });
}));

// ── PRÉFÉRENCES DE NOTIFICATION ─────────────────────────────────────────────────

// GET /api/admin/notification-prefs
app.get('/api/admin/notification-prefs', requireAuth, wrap(async (req, res) => {
  const { lastRecapSentDate, ...prefs } = await getPrefs();
  res.json(prefs);
}));

// PUT /api/admin/notification-prefs
app.put('/api/admin/notification-prefs', requireAuth, wrap(async (req, res) => {
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
}));

// ── HEALTH CHECK ──────────────────────────────────────────────────────────────
// GET /api/config — tarifs, durées et jours travaillés.
// Publique : ces informations figurent déjà sur le site. Elle existe pour que
// l'app iOS cesse de les redéclarer en dur de son côté.
app.get('/api/config', (_, res) => res.json({
  prices: SESSION_PRICES,
  durations: SESSION_DURATIONS,
  workingDays: WORKING_DAYS,
  typeLabels: TYPE_LABELS,
  paymentMethods: PAYMENT_METHODS,
}));

app.get('/api/health', (_, res) => res.json({
  status: 'ok',
  time: new Date().toISOString(),
  apnConfigured: apnProvider !== null,
  dbConnected: db !== null,
  stripeConfigured: stripe !== null,
  emailConfigured,
}));

// ── MIDDLEWARE D'ERREUR ───────────────────────────────────────────────────────
// Dernier maillon : toute erreur remontée par `wrap` arrive ici. On journalise
// le détail côté serveur et on renvoie un message générique au client, pour ne
// pas exposer de trace interne.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(`Erreur non gérée sur ${req.method} ${req.originalUrl} :`, err);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Une erreur est survenue. Réessayez dans un instant.' });
});

// Filet de sécurité : si une erreur échappe malgré tout à Express (timer,
// callback détaché…), on la journalise sans laisser Node arrêter le processus.
process.on('unhandledRejection', reason => {
  console.error('Rejet de promesse non géré :', reason);
});
process.on('uncaughtException', err => {
  console.error('Exception non interceptée :', err);
});

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

  // Garde-fou anti-double-réservation : deux requêtes simultanées sur le même
  // créneau passent toutes les deux checkSlotAvailable(), qui n'est pas atomique.
  // L'index rejette la seconde écriture (erreur 11000 → 409 côté client).
  // Filtré sur les RDV confirmés : un créneau annulé reste réservable.
  // Créé à part car il peut échouer si la base contient déjà un doublon
  // historique — dans ce cas on continue de démarrer, avec un avertissement.
  try {
    await db.collection('bookings').createIndex(
      { date: 1, startTime: 1 },
      { unique: true, partialFilterExpression: { status: 'confirmed' } }
    );
  } catch (e) {
    console.error(
      'Index anti-double-réservation non créé (doublon existant en base ?) :',
      e.message,
      '\nLe serveur démarre quand même, mais la protection atomique est inactive.'
    );
  }

  console.log('Connecté à MongoDB.');

  setInterval(() => {
    checkDailyRecap().catch(e => console.error('Erreur récap quotidien :', e.message));
  }, 60 * 1000);

  // Purge de conservation : une fois au démarrage, puis une fois par jour.
  purgeExpiredPersonalData().catch(e => console.error('Erreur purge RGPD :', e.message));
  setInterval(() => {
    purgeExpiredPersonalData().catch(e => console.error('Erreur purge RGPD :', e.message));
  }, 24 * 60 * 60 * 1000);
  console.log(
    RETENTION_ENABLED
      ? `Conservation des données : anonymisation après ${RETENTION_YEARS} ans sans contact.`
      : 'Conservation des données : purge automatique DÉSACTIVÉE (DATA_RETENTION_ENABLED=false).'
  );

  app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT}`));
}

start().catch(e => {
  console.error('Échec du démarrage :', e.message);
  process.exit(1);
});
