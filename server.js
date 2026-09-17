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
const LOCK_AFTER_ATTEMPTS = 5;
const LOCK_MINUTES = 5;
const INITIAL_FLIGHTS = ["Premier Flight","Flight 1","Flight 2","Flight 3","Flight 4A","Flight 4B"];

/* ===================================================================
   DATABASE — Firestore
   =================================================================== */
const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, "base64").toString("utf8")
);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const flights = db.collection("flights");
const metaFlightsRef = db.collection("meta").doc("flights");

const DEFAULT_FLIGHT = {
  pinHash: null, adminName: "",
  recoveryCodeHash: null,
  tokenVersion: 0, failedAttempts: 0, lockUntil: null,
  lastActiveAt: null,
  tubePriceFils: 14500, shuttlesPerTube: 12, shuttlesInStock: 0,
  members: [], sessions: [], paid: {}
};

function genToken(){ return crypto.randomBytes(12).toString("hex"); }

async function getFlightNames(){
  const snap = await metaFlightsRef.get();
  if(!snap.exists){
    await metaFlightsRef.set({ names: INITIAL_FLIGHTS });
    return [...INITIAL_FLIGHTS];
  }
  return snap.data().names || [];
}
async function setFlightNames(names){
  await metaFlightsRef.set({ names });
}

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
  const { pinHash, recoveryCodeHash, ...rest } = data;
  return { flightName: name, ...rest, hasPin: !!pinHash, hasRecoveryCode: !!recoveryCodeHash };
}

/* ===================================================================
   PUBLIC (no auth)
   =================================================================== */
app.get("/api/ping", (req, res) => res.json({ ok: true }));
app.get("/api/flights", async (req, res) => res.json(await getFlightNames()));

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
   LOGIN + RECOVERY (flight admins)
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
  const names = await getFlightNames();
  if(!names.includes(flightName)) return res.status(400).json({ message: "Unknown flight." });
  if(!/^\d{4,6}$/.test(pin || "")) return res.status(400).json({ message: "PIN must be 4–6 digits." });

  const { ref, data } = await getOrCreateFlight(flightName);
  if(isLocked(data)) return res.status(429).json({ message: lockMessage(data) });

  if(!data.pinHash){
    data.pinHash = await bcrypt.hash(pin, 10);
    data.failedAttempts = 0; data.lockUntil = null;
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
  }

  data.lastActiveAt = new Date().toISOString();
  await ref.set(data);

  const token = jwt.sign({ flightName, tokenVersion: data.tokenVersion || 0 }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, flight: publicFlight(flightName, data) });
});

app.post("/api/recover/pin", async (req, res) => {
  const { flightName, recoveryCode, newPin } = req.body;
  const names = await getFlightNames();
  if(!names.includes(flightName)) return res.status(400).json({ message: "Unknown flight." });
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });

  const { ref, data } = await getOrCreateFlight(flightName);
  if(!data.recoveryCodeHash) return res.status(400).json({ message: "No recovery code has been set for this flight yet." });
  const ok = await bcrypt.compare(String(recoveryCode || ""), data.recoveryCodeHash);
  if(!ok) return res.status(401).json({ message: "That recovery code doesn't match." });

  data.pinHash = await bcrypt.hash(newPin, 10);
  data.tokenVersion = (data.tokenVersion || 0) + 1;
  data.failedAttempts = 0; data.lockUntil = null;
  await ref.set(data);
  res.json({ success: true });
});

/* ===================================================================
   OWNER — Firebase Auth email/password. Flight list management only.
   =================================================================== */
async function ownerMiddleware(req, res, next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if(!token) return res.status(401).json({ message: "Not signed in as owner." });
  try{
    await admin.auth().verifyIdToken(token);
    next();
  }catch{
    res.status(401).json({ message: "Owner session expired — please sign in again." });
  }
}

app.get("/api/owner/flights", ownerMiddleware, async (req, res) => {
  const names = await getFlightNames();
  const list = [];
  for(const name of names){
    const { data } = await getOrCreateFlight(name);
    list.push({
      name,
      claimed: !!data.pinHash,
      adminName: data.adminName || "",
      memberCount: data.members.length,
      sessionCount: data.sessions.length,
      lastActiveAt: data.lastActiveAt || null
    });
  }
  res.json(list);
});

app.post("/api/owner/flights", ownerMiddleware, async (req, res) => {
  const name = String(req.body.name || "").trim();
  if(!name) return res.status(400).json({ message: "Enter a flight name." });
  const names = await getFlightNames();
  if(names.includes(name)) return res.status(409).json({ message: "That flight name already exists." });
  names.push(name);
  await setFlightNames(names);
  await flights.doc(name).set(DEFAULT_FLIGHT);
  res.json({ success: true });
});

app.patch("/api/owner/flights/:name/rename", ownerMiddleware, async (req, res) => {
  const oldName = req.params.name;
  const newName = String(req.body.newName || "").trim();
  if(!newName) return res.status(400).json({ message: "Enter a new name." });
  const names = await getFlightNames();
  if(!names.includes(oldName)) return res.status(404).json({ message: "Flight not found." });
  if(names.includes(newName)) return res.status(409).json({ message: "That name is already taken." });

  const oldRef = flights.doc(oldName);
  const snap = await oldRef.get();
  const data = snap.exists ? snap.data() : { ...DEFAULT_FLIGHT };
  await flights.doc(newName).set(data);
  await oldRef.delete();

  await setFlightNames(names.map(n => n === oldName ? newName : n));
  res.json({ success: true });
});

// Revoke access: clears PIN + recovery code + expires all existing logins.
// Members, sessions, payments, stock, and settings are completely untouched.
app.post("/api/owner/flights/:name/revoke", ownerMiddleware, async (req, res) => {
  const name = req.params.name;
  const names = await getFlightNames();
  if(!names.includes(name)) return res.status(404).json({ message: "Flight not found." });

  const { ref, data } = await getOrCreateFlight(name);
  data.pinHash = null;
  data.recoveryCodeHash = null;
  data.tokenVersion = (data.tokenVersion || 0) + 1;
  data.failedAttempts = 0;
  data.lockUntil = null;
  await ref.set(data);
  res.json({ success: true });
});

app.delete("/api/owner/flights/:name", ownerMiddleware, async (req, res) => {
  const name = req.params.name;
  const names = await getFlightNames();
  if(!names.includes(name)) return res.status(404).json({ message: "Flight not found." });

  await flights.doc(name).delete();
  await setFlightNames(names.filter(n => n !== name));
  res.json({ success: true });
});

/* ===================================================================
   AUTHENTICATED FLIGHT ROUTES
   =================================================================== */
function authMiddleware(req, res, next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if(!token) return res.status(401).json({ message: "Not signed in." });
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    if(!payload.flightName) throw new Error("no flight in token");
    req.flightName = payload.flightName;
    req.tokenVersion = payload.tokenVersion || 0;
    next();
  }catch{
    res.status(401).json({ message: "Session expired — please sign in again." });
  }
}
app.use("/api", authMiddleware);

async function loadFlightChecked(req, res){
  const names = await getFlightNames();
  if(!names.includes(req.flightName)){
    res.status(401).json({ message: "This flight no longer exists — please sign in again." });
    return null;
  }
  const { ref, data } = await getOrCreateFlight(req.flightName);
  if((data.tokenVersion || 0) !== req.tokenVersion){
    res.status(401).json({ message: "Your session was ended — please sign in again." });
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
  const { adminName, tubePriceFils, shuttlesPerTube, addTubes, setStockExact } = req.body;
  if(!(tubePriceFils > 0)) return res.status(400).json({ message: "Enter a tube price greater than zero." });
  if(!(shuttlesPerTube > 0)) return res.status(400).json({ message: "Enter how many shuttles are in a tube." });
  data.adminName = String(adminName || "").trim();
  data.tubePriceFils = Math.round(tubePriceFils);
  data.shuttlesPerTube = Math.round(shuttlesPerTube);

  if(setStockExact !== undefined && setStockExact !== null && String(setStockExact).trim() !== ""){
    data.shuttlesInStock = Math.max(0, Math.round(Number(setStockExact)));
  } else {
    const tubesToAdd = Math.max(0, Math.round(Number(addTubes) || 0));
    data.shuttlesInStock = (data.shuttlesInStock || 0) + tubesToAdd * data.shuttlesPerTube;
  }

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
  res.json({ success: true });
});

app.post("/api/flight/recovery-code", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  const code = String(req.body.recoveryCode || "").trim();
  if(code.length < 4) return res.status(400).json({ message: "Recovery code should be at least 4 characters." });
  data.recoveryCodeHash = await bcrypt.hash(code, 10);
  await ref.set(data);
  res.json({ success: true });
});

app.post("/api/flight/stock/reset", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  data.shuttlesInStock = 0;
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.delete("/api/flight/members/clear-all", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  data.members = [];
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.delete("/api/flight/sessions/clear-all", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data } = ctx;
  data.sessions = [];
  data.paid = {};
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
    tokenVersion: data.tokenVersion, adminName: data.adminName, lastActiveAt: data.lastActiveAt,
    tubePriceFils: data.tubePriceFils, shuttlesPerTube: data.shuttlesPerTube };
  await ref.set(fresh);
  res.json(publicFlight(req.flightName, fresh));
});

app.get(/^(?!\/api).*/, (req, res) => res.sendFile(path.join(__dirname, "public/index.html")));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Shuttle server running on port ${PORT}`));
