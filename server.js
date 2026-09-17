import express from "express";
import admin from "firebase-admin";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const JWT_SECRET = process.env.JWT_SECRET;
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL;
const FLIGHT_NAMES = ["Premier Flight","Flight 1","Flight 2","Flight 3","Flight 4A","Flight 4B"];

const LOCK_AFTER_ATTEMPTS = 5;
const LOCK_MINUTES = 5;
const RESET_CODE_MINUTES = 10;

/* ===================================================================
   DATABASE — Firestore, one document per flight
   =================================================================== */
const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, "base64").toString("utf8")
);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const flights = db.collection("flights");

const DEFAULT_FLIGHT = {
  pinHash: null, adminName: "",
  recoveryCodeHash: null,
  email: "", emailVerified: false, emailPendingCode: null, emailPendingExpiresAt: null,
  emailResetCode: null, emailResetExpiresAt: null,
  tokenVersion: 0, failedAttempts: 0, lockUntil: null,
  tubePriceFils: 14500, shuttlesPerTube: 12, shuttlesInStock: 0,
  members: [], sessions: [], paid: {}
};

function genToken(){ return crypto.randomBytes(12).toString("hex"); }
function gen6Digit(){ return String(Math.floor(100000 + Math.random() * 900000)); }

async function getOrCreateFlight(name){
  const ref = flights.doc(name);
  const snap = await ref.get();
  if(!snap.exists){
    await ref.set(DEFAULT_FLIGHT);
    return { ref, data: { ...DEFAULT_FLIGHT } };
  }
  const data = { ...DEFAULT_FLIGHT, ...snap.data() };
  return { ref, data };
}

async function sendEmail(to, subject, html){
  if(!BREVO_API_KEY || !BREVO_SENDER_EMAIL){
    throw new Error("Email isn't configured yet — ask the admin to set up email sending.");
  }
  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "Content-Type": "application/json", "api-key": BREVO_API_KEY },
    body: JSON.stringify({
      sender: { email: BREVO_SENDER_EMAIL, name: "Shuttle Session Manager" },
      to: [{ email: to }],
      subject, htmlContent: html
    })
  });
  if(!res.ok){
    const body = await res.text().catch(() => "");
    throw new Error("Couldn't send the email right now. " + body.slice(0,200));
  }
}

/* ===================================================================
   CORE CALCULATION
   =================================================================== */
function pricePerShuttleFils(tubePriceFils, shuttlesPerTube){ return tubePriceFils / shuttlesPerTube; }
function dayCostFils(tubePriceFils, shuttlesPerTube, used){
  return Math.round(used * pricePerShuttleFils(tubePriceFils, shuttlesPerTube));
}
function splitShares(totalFils, presentIds){
  const ids = [...new Set(presentIds)].sort();
  if(!ids.length) return {};
  const base = Math.floor(totalFils / ids.length);
  const remainder = totalFils % ids.length;
  const shares = {};
  ids.forEach((id,i) => { shares[id] = base + (i < remainder ? 1 : 0); });
  return shares;
}
function paidAmountFor(data, key, shareFils){
  const v = data.paid[key];
  if(v === true) return shareFils;
  return Number(v) || 0;
}
function outstandingFils(data, memberId){
  return data.sessions.reduce((sum,s) => {
    const share = s.shares[memberId];
    if(!share) return sum;
    const paid = paidAmountFor(data, `${s.id}_${memberId}`, share);
    return sum + Math.max(0, share - paid);
  }, 0);
}
function publicFlight(name, data){
  const { pinHash, recoveryCodeHash, emailPendingCode, emailResetCode, ...rest } = data;
  return { flightName: name, ...rest, hasPin: !!pinHash, hasRecoveryCode: !!recoveryCodeHash };
}

/* ===================================================================
   PUBLIC (no auth)
   =================================================================== */
app.get("/api/ping", (req, res) => res.json({ ok: true }));
app.get("/api/flights", (req, res) => res.json(FLIGHT_NAMES));

app.get("/api/public/:token", async (req, res) => {
  const snapshot = await flights.get();
  for(const doc of snapshot.docs){
    const data = { ...DEFAULT_FLIGHT, ...doc.data() };
    const m = (data.members || []).find(x => x.publicToken === req.params.token);
    if(m){
      const owed = outstandingFils(data, m.id);
      const unpaid = data.sessions.filter(s => {
        const share = s.shares[m.id];
        if(!share) return false;
        return paidAmountFor(data, `${s.id}_${m.id}`, share) < share;
      }).map(s => {
        const share = s.shares[m.id];
        const paid = paidAmountFor(data, `${s.id}_${m.id}`, share);
        return { date: s.date, dueFils: share - paid };
      });
      return res.json({ flightName: doc.id, memberName: m.name, outstandingFils: owed, unpaidGames: unpaid });
    }
  }
  res.status(404).json({ message: "Link not found or expired." });
});

/* ===================================================================
   LOGIN + RECOVERY (no auth token needed yet)
   =================================================================== */
function isLocked(data){
  return data.lockUntil && new Date(data.lockUntil).getTime() > Date.now();
}
function lockMessage(data){
  const mins = Math.ceil((new Date(data.lockUntil).getTime() - Date.now()) / 60000);
  return `Too many wrong attempts. Try again in ${mins} minute(s).`;
}

app.post("/api/login", async (req, res) => {
  const { flightName, pin } = req.body;
  if(!FLIGHT_NAMES.includes(flightName)) return res.status(400).json({ message: "Unknown flight." });
  if(!/^\d{4,6}$/.test(pin || "")) return res.status(400).json({ message: "PIN must be 4–6 digits." });

  const { ref, data } = await getOrCreateFlight(flightName);
  if(isLocked(data)) return res.status(429).json({ message: lockMessage(data) });

  if(!data.pinHash){
    data.pinHash = await bcrypt.hash(pin, 10);
    data.failedAttempts = 0; data.lockUntil = null;
    await ref.set(data);
  }else{
    const ok = await bcrypt.compare(pin, data.pinHash);
    if(!ok){
      data.failedAttempts = (data.failedAttempts || 0) + 1;
      if(data.failedAttempts >= LOCK_AFTER_ATTEMPTS){
        data.lockUntil = new Date(Date.now() + LOCK_MINUTES * 60000).toISOString();
        data.failedAttempts = 0;
      }
      await ref.set(data);
      return res.status(401).json({ message: "Incorrect PIN." });
    }
    data.failedAttempts = 0; data.lockUntil = null;
    await ref.set(data);
  }

  const token = jwt.sign({ flightName, tokenVersion: data.tokenVersion || 0 }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, flight: publicFlight(flightName, data) });
});

// Reset PIN using the recovery code — fully self-service, no admin involvement.
app.post("/api/recover/pin", async (req, res) => {
  const { flightName, recoveryCode, newPin } = req.body;
  if(!FLIGHT_NAMES.includes(flightName)) return res.status(400).json({ message: "Unknown flight." });
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });

  const { ref, data } = await getOrCreateFlight(flightName);
  if(!data.recoveryCodeHash) return res.status(400).json({ message: "No recovery code has been set for this flight yet." });
  const ok = await bcrypt.compare(String(recoveryCode || ""), data.recoveryCodeHash);
  if(!ok) return res.status(401).json({ message: "That recovery code doesn't match." });

  data.pinHash = await bcrypt.hash(newPin, 10);
  data.tokenVersion = (data.tokenVersion || 0) + 1; // force-expire any existing logins
  data.failedAttempts = 0; data.lockUntil = null;
  await ref.set(data);
  res.json({ success: true });
});

// Step 1 of email-based reset: send a 6-digit code to the flight's verified email.
app.post("/api/recover/email/request", async (req, res) => {
  const { flightName } = req.body;
  if(!FLIGHT_NAMES.includes(flightName)) return res.status(400).json({ message: "Unknown flight." });
  const { ref, data } = await getOrCreateFlight(flightName);
  if(!data.email || !data.emailVerified) return res.status(400).json({ message: "No verified email on file for this flight." });

  const code = gen6Digit();
  data.emailResetCode = code;
  data.emailResetExpiresAt = new Date(Date.now() + RESET_CODE_MINUTES * 60000).toISOString();
  await ref.set(data);

  try{
    await sendEmail(data.email, "Your Shuttle Session Manager reset code",
      `<p>Your PIN reset code for <strong>${flightName}</strong> is:</p><h2>${code}</h2><p>This code expires in ${RESET_CODE_MINUTES} minutes.</p>`);
  }catch(err){ return res.status(500).json({ message: err.message }); }

  res.json({ success: true, message: "Reset code sent to your email." });
});

// Step 2 of email-based reset: confirm the code, set the new PIN.
app.post("/api/recover/email/confirm", async (req, res) => {
  const { flightName, code, newPin } = req.body;
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });
  const { ref, data } = await getOrCreateFlight(flightName);
  if(!data.emailResetCode || !data.emailResetExpiresAt || new Date(data.emailResetExpiresAt) < new Date()){
    return res.status(400).json({ message: "That code has expired — request a new one." });
  }
  if(String(code) !== data.emailResetCode) return res.status(401).json({ message: "Incorrect code." });

  data.pinHash = await bcrypt.hash(newPin, 10);
  data.emailResetCode = null; data.emailResetExpiresAt = null;
  data.tokenVersion = (data.tokenVersion || 0) + 1;
  data.failedAttempts = 0; data.lockUntil = null;
  await ref.set(data);
  res.json({ success: true });
});

/* ===================================================================
   AUTHENTICATED ROUTES
   =================================================================== */
function authMiddleware(req, res, next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if(!token) return res.status(401).json({ message: "Not signed in." });
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.flightName = payload.flightName;
    req.tokenVersion = payload.tokenVersion || 0;
    next();
  }catch{
    res.status(401).json({ message: "Session expired — please sign in again." });
  }
}
app.use("/api", authMiddleware);

// Every authenticated route re-checks tokenVersion against the flight's current
// value, so a PIN reset (recovery, email, or manual change) immediately kicks
// out anyone still using an old token — no separate revoke list needed.
async function loadFlightChecked(req, res){
  const { ref, data } = await getOrCreateFlight(req.flightName);
  if((data.tokenVersion || 0) !== req.tokenVersion){
    res.status(401).json({ message: "Your PIN was reset elsewhere — please sign in again." });
    return null;
  }
  return { ref, data };
}

app.get("/api/flight", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  res.json(publicFlight(req.flightName, ctx.data));
});

app.post("/api/flight/settings", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const { adminName, tubePriceFils, shuttlesPerTube, addTubes } = req.body;
  if(!(tubePriceFils > 0)) return res.status(400).json({ message: "Enter a tube price greater than zero." });
  if(!(shuttlesPerTube > 0)) return res.status(400).json({ message: "Enter how many shuttles are in a tube." });
  data.adminName = String(adminName || "").trim();
  data.tubePriceFils = Math.round(tubePriceFils);
  data.shuttlesPerTube = Math.round(shuttlesPerTube);
  const tubesToAdd = Math.max(0, Math.round(Number(addTubes) || 0));
  data.shuttlesInStock = (data.shuttlesInStock || 0) + tubesToAdd * data.shuttlesPerTube;
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/flight/pin", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const { oldPin, newPin } = req.body;
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });
  const ok = await bcrypt.compare(oldPin || "", data.pinHash);
  if(!ok) return res.status(401).json({ message: "Current PIN is incorrect." });
  data.pinHash = await bcrypt.hash(newPin, 10);
  data.tokenVersion = (data.tokenVersion || 0) + 1;
  await ref.set(data);
  res.json({ success: true, tokenVersion: data.tokenVersion });
});

// Set/replace the recovery code — just needs to be logged in already.
app.post("/api/flight/recovery-code", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const code = String(req.body.recoveryCode || "").trim();
  if(code.length < 4) return res.status(400).json({ message: "Recovery code should be at least 4 characters." });
  data.recoveryCodeHash = await bcrypt.hash(code, 10);
  await ref.set(data);
  res.json({ success: true });
});

// Set an email + send it a verification code.
app.post("/api/flight/email/request", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const email = String(req.body.email || "").trim();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: "Enter a valid email address." });

  const code = gen6Digit();
  data.emailPendingCode = code;
  data.emailPendingExpiresAt = new Date(Date.now() + RESET_CODE_MINUTES * 60000).toISOString();
  data.email = email; data.emailVerified = false;
  await ref.set(data);

  try{
    await sendEmail(email, "Verify your email for Shuttle Session Manager",
      `<p>Your verification code is:</p><h2>${code}</h2><p>This code expires in ${RESET_CODE_MINUTES} minutes.</p>`);
  }catch(err){ return res.status(500).json({ message: err.message }); }

  res.json({ success: true, message: "Verification code sent." });
});

app.post("/api/flight/email/confirm", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const code = String(req.body.code || "").trim();
  if(!data.emailPendingCode || !data.emailPendingExpiresAt || new Date(data.emailPendingExpiresAt) < new Date()){
    return res.status(400).json({ message: "That code has expired — request a new one." });
  }
  if(code !== data.emailPendingCode) return res.status(401).json({ message: "Incorrect code." });
  data.emailVerified = true;
  data.emailPendingCode = null; data.emailPendingExpiresAt = null;
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/members", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const name = String(req.body.name || "").trim();
  const phone = String(req.body.phone || "").trim();
  if(!name) return res.status(400).json({ message: "Type a name first." });
  if(data.members.some(m => m.name.toLowerCase() === name.toLowerCase())){
    return res.status(409).json({ message: "That name is already in this flight." });
  }
  data.members.push({
    id: "m" + Date.now().toString(36) + Math.random().toString(36).slice(2,6),
    name, phone, publicToken: genToken(), active: true
  });
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.patch("/api/members/:id/toggle", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const m = data.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  m.active = !m.active;
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.patch("/api/members/:id", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const { name, phone } = req.body;
  const m = data.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  if(name !== undefined){
    const n = String(name).trim();
    if(!n) return res.status(400).json({ message: "Name required." });
    m.name = n;
  }
  if(phone !== undefined) m.phone = String(phone).trim();
  if(!m.publicToken) m.publicToken = genToken();
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.delete("/api/members/:id", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const m = data.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  const owed = outstandingFils(data, m.id);
  if(owed > 0) return res.status(409).json({ message: `${m.name} still owes BHD ${(owed/1000).toFixed(3)} — settle that first.` });
  data.members = data.members.filter(x => x.id !== req.params.id);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/sessions", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const { date, shuttlesUsed, presentIds, createdBy } = req.body;
  if(!date) return res.status(400).json({ message: "Pick the game date." });
  if(!Number.isInteger(shuttlesUsed) || shuttlesUsed <= 0) return res.status(400).json({ message: "Enter how many shuttles were used." });
  if(!Array.isArray(presentIds) || !presentIds.length) return res.status(400).json({ message: "Mark at least one player present." });
  if(shuttlesUsed > (data.shuttlesInStock || 0)){
    return res.status(400).json({ message: `Only ${data.shuttlesInStock || 0} shuttle(s) in stock — restock before saving this game.` });
  }

  const total = dayCostFils(data.tubePriceFils, data.shuttlesPerTube, shuttlesUsed);
  const shares = splitShares(total, presentIds);

  data.sessions.push({
    id: "s" + Date.now().toString(36) + Math.random().toString(36).slice(2,6),
    date, shuttlesUsed, presentIds, totalCostFils: total, shares,
    createdBy: String(createdBy || "").trim(),
    createdAt: new Date().toISOString()
  });
  data.shuttlesInStock = (data.shuttlesInStock || 0) - shuttlesUsed;

  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.delete("/api/sessions/:id", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const session = data.sessions.find(s => s.id === req.params.id);
  data.sessions = data.sessions.filter(s => s.id !== req.params.id);
  Object.keys(data.paid).forEach(k => { if(k.startsWith(req.params.id + "_")) delete data.paid[k]; });
  if(session) data.shuttlesInStock = (data.shuttlesInStock || 0) + session.shuttlesUsed;
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/payments/:sessionId/:memberId/pay-partial", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const amountFils = Math.round(Number(req.body.amountFils) || 0);
  if(amountFils <= 0) return res.status(400).json({ message: "Enter an amount greater than zero." });
  const key = `${req.params.sessionId}_${req.params.memberId}`;
  const session = data.sessions.find(s => s.id === req.params.sessionId);
  const share = session?.shares[req.params.memberId] || 0;
  const already = paidAmountFor(data, key, share);
  data.paid[key] = Math.min(share, already + amountFils);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/payments/:memberId/settle-all", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  data.sessions.forEach(s => { if(s.shares[req.params.memberId]) data.paid[`${s.id}_${req.params.memberId}`] = s.shares[req.params.memberId]; });
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.delete("/api/flight/reset", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const fresh = { ...DEFAULT_FLIGHT, pinHash: data.pinHash, recoveryCodeHash: data.recoveryCodeHash,
    email: data.email, emailVerified: data.emailVerified, tokenVersion: data.tokenVersion,
    adminName: data.adminName, tubePriceFils: data.tubePriceFils, shuttlesPerTube: data.shuttlesPerTube };
  await ref.set(fresh);
  res.json(publicFlight(req.flightName, fresh));
});

app.get(/^(?!\/api).*/, (req, res) => res.sendFile(path.join(__dirname, "public/index.html")));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Shuttle server running on port ${PORT}`));
