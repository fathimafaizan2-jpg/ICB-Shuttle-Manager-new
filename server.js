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

// A function, not a shared object — every call returns a brand-new set of
// arrays/objects, so no two flights can ever accidentally reference the same one.
function defaultFlight(){
  return {
    admins: [], // {id, name, pinHash, mustChangePin, recoveryCodeHash, tokenVersion, failedAttempts, lockUntil, lastActiveAt}
    tubePriceFils: 14500, shuttlesPerTube: 12, shuttlesInStock: 0,
    members: [], sessions: [], paid: {},
    auditLog: [] // {ts, actor, action}
  };
}

function genToken(){ return crypto.randomBytes(12).toString("hex"); }
function genId(prefix){ return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2,6); }

function findAdmin(data, name){
  return (data.admins || []).find(a => a.name.trim().toLowerCase() === String(name).trim().toLowerCase());
}
function findAdminById(data, id){
  return (data.admins || []).find(a => a.id === id);
}
function publicAdminList(data){
  return (data.admins || []).map(a => ({ id: a.id, name: a.name }));
}
function ensureMemberForAdmin(data, name){
  const exists = data.members.some(m => m.name.trim().toLowerCase() === name.trim().toLowerCase());
  if(!exists){
    data.members.push({ id: genId("m"), name: name.trim(), phone:"", publicToken: genToken(), active:true });
  }
}
function logEvent(data, actor, action){
  if(!data.auditLog) data.auditLog = [];
  data.auditLog.push({ ts: new Date().toISOString(), actor: actor || "Unknown", action });
  if(data.auditLog.length > 300) data.auditLog = data.auditLog.slice(-300);
}

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
    const fresh = defaultFlight();
    await ref.set(fresh);
    return { ref, data: fresh };
  }
  const data = { ...defaultFlight(), ...snap.data() };
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
function memberNameById(members, id){
  const m = members.find(x => x.id === id);
  return m ? m.name : "Unknown";
}
function publicFlight(name, data, currentAdminId){
  const current = currentAdminId ? findAdminById(data, currentAdminId) : null;
  return {
    flightName: name,
    tubePriceFils: data.tubePriceFils,
    shuttlesPerTube: data.shuttlesPerTube,
    shuttlesInStock: data.shuttlesInStock,
    members: data.members,
    sessions: data.sessions,
    paid: data.paid,
    admins: publicAdminList(data),
    currentAdmin: current ? {
      id: current.id, name: current.name,
      mustChangePin: !!current.mustChangePin,
      hasRecoveryCode: !!current.recoveryCodeHash
    } : null,
    auditLog: (data.auditLog || []).slice(-100).reverse()
  };
}

/* ===================================================================
   PUBLIC (no auth)
   =================================================================== */
app.get("/api/ping", (req, res) => res.json({ ok: true }));
app.get("/api/flights", async (req, res) => res.json(await getFlightNames()));

app.get("/api/public/:token", async (req, res) => {
  const snapshot = await flights.get();
  for(const doc of snapshot.docs){
    const data = { ...defaultFlight(), ...doc.data() };
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
   LOGIN + RECOVERY (per-admin, name + PIN both required, always)
   =================================================================== */
function isLocked(entity){
  return entity.lockUntil && new Date(entity.lockUntil).getTime() > Date.now();
}
function lockMessage(entity){
  const mins = Math.ceil((new Date(entity.lockUntil).getTime() - Date.now()) / 60000);
  return `Too many wrong attempts. Try again in ${mins} minute(s).`;
}

app.post("/api/login", async (req, res) => {
  const { flightName, adminName, pin } = req.body;
  const names = await getFlightNames();
  if(!names.includes(flightName)) return res.status(400).json({ message: "Unknown flight." });
  if(!String(adminName || "").trim()) return res.status(400).json({ message: "Enter your name." });
  if(!/^\d{4,6}$/.test(pin || "")) return res.status(400).json({ message: "PIN must be 4–6 digits." });

  const { ref, data } = await getOrCreateFlight(flightName);
  const a = findAdmin(data, adminName);
  if(!a || !a.pinHash){
    return res.status(400).json({ message: "No admin account found — contact your club Super Admin or an existing admin." });
  }
  if(isLocked(a)) return res.status(429).json({ message: lockMessage(a) });

  const ok = await bcrypt.compare(pin, a.pinHash);
  if(!ok){
    a.failedAttempts = (a.failedAttempts || 0) + 1;
    if(a.failedAttempts >= LOCK_AFTER_ATTEMPTS){
      a.lockUntil = new Date(Date.now() + LOCK_MINUTES * 60000).toISOString();
      a.failedAttempts = 0;
    }
    await ref.set(data);
    return res.status(401).json({ message: "Incorrect name or PIN." });
  }

  a.failedAttempts = 0; a.lockUntil = null;
  a.lastActiveAt = new Date().toISOString();
  logEvent(data, a.name, "Signed in");
  await ref.set(data);

  const token = jwt.sign({ flightName, adminId: a.id, tokenVersion: a.tokenVersion || 0 }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, flight: publicFlight(flightName, data, a.id) });
});

app.post("/api/recover/pin", async (req, res) => {
  const { flightName, adminName, recoveryCode, newPin } = req.body;
  const names = await getFlightNames();
  if(!names.includes(flightName)) return res.status(400).json({ message: "Unknown flight." });
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });

  const { ref, data } = await getOrCreateFlight(flightName);
  const a = findAdmin(data, adminName);
  if(!a) return res.status(400).json({ message: "No admin account found with that name." });
  if(!a.recoveryCodeHash) return res.status(400).json({ message: "No recovery code has been set for this admin yet." });
  const ok = await bcrypt.compare(String(recoveryCode || ""), a.recoveryCodeHash);
  if(!ok) return res.status(401).json({ message: "That recovery code doesn't match." });

  a.pinHash = await bcrypt.hash(newPin, 10);
  a.mustChangePin = false;
  a.tokenVersion = (a.tokenVersion || 0) + 1;
  a.failedAttempts = 0; a.lockUntil = null;
  logEvent(data, a.name, "Reset their own PIN via recovery code");
  await ref.set(data);
  res.json({ success: true });
});

/* ===================================================================
   SUPER ADMIN — Firebase Auth email/password.
   =================================================================== */
async function ownerMiddleware(req, res, next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if(!token) return res.status(401).json({ message: "Not signed in as Super Admin." });
  try{
    await admin.auth().verifyIdToken(token);
    next();
  }catch{
    res.status(401).json({ message: "Super Admin session expired — please sign in again." });
  }
}

app.get("/api/owner/flights", ownerMiddleware, async (req, res) => {
  const names = await getFlightNames();
  const list = [];
  for(const name of names){
    const { data } = await getOrCreateFlight(name);
    const admins = data.admins || [];
    const lastActiveAt = admins.reduce((max,a) => (a.lastActiveAt && (!max || a.lastActiveAt > max)) ? a.lastActiveAt : max, null);
    list.push({
      name,
      claimed: admins.some(a => a.pinHash),
      adminNames: admins.map(a => a.name),
      memberCount: data.members.length,
      sessionCount: data.sessions.length,
      lastActiveAt
    });
  }
  res.json(list);
});

app.get("/api/owner/flights/:name/logs", ownerMiddleware, async (req, res) => {
  const name = req.params.name;
  const names = await getFlightNames();
  if(!names.includes(name)) return res.status(404).json({ message: "Flight not found." });
  const { data } = await getOrCreateFlight(name);
  res.json({
    flightName: name,
    members: data.members.map(m => ({ id:m.id, name:m.name, active:m.active })),
    sessions: data.sessions,
    auditLog: (data.auditLog || []).slice().reverse()
  });
});

app.post("/api/owner/flights", ownerMiddleware, async (req, res) => {
  const name = String(req.body.name || "").trim();
  const adminName = String(req.body.adminName || "").trim();
  const initialPin = String(req.body.initialPin || "").trim();
  if(!name) return res.status(400).json({ message: "Enter a flight name." });
  if(adminName && !initialPin) return res.status(400).json({ message: "Set an initial PIN for that admin." });
  if(initialPin && !/^\d{4,6}$/.test(initialPin)) return res.status(400).json({ message: "Initial PIN must be 4–6 digits." });

  const names = await getFlightNames();
  if(names.includes(name)) return res.status(409).json({ message: "That flight name already exists." });
  names.push(name);
  await setFlightNames(names);

  const flightDoc = defaultFlight();
  if(adminName && initialPin){
    const a = { id: genId("a"), name: adminName, pinHash: await bcrypt.hash(initialPin, 10),
      mustChangePin: true, recoveryCodeHash: null, tokenVersion: 0, failedAttempts: 0, lockUntil: null, lastActiveAt: null };
    flightDoc.admins.push(a);
    flightDoc.members.push({ id: genId("m"), name: adminName, phone:"", publicToken: genToken(), active:true });
    logEvent(flightDoc, "Super Admin", `Created flight and added admin: ${adminName}`);
  } else {
    logEvent(flightDoc, "Super Admin", "Created flight");
  }
  await flights.doc(name).set(flightDoc);
  res.json({ success: true });
});

// Add a brand-new admin, or reissue a PIN for an existing one by name.
app.post("/api/owner/flights/:name/assign", ownerMiddleware, async (req, res) => {
  const name = req.params.name;
  const names = await getFlightNames();
  if(!names.includes(name)) return res.status(404).json({ message: "Flight not found." });
  const { ref, data } = await getOrCreateFlight(name);

  const adminName = String(req.body.adminName || "").trim();
  const newPin = String(req.body.newPin || "").trim();
  if(!adminName) return res.status(400).json({ message: "Enter an admin name." });
  if(!/^\d{4,6}$/.test(newPin)) return res.status(400).json({ message: "Enter a 4–6 digit PIN." });

  let a = findAdmin(data, adminName);
  if(a){
    a.pinHash = await bcrypt.hash(newPin, 10);
    a.mustChangePin = true;
    a.tokenVersion = (a.tokenVersion || 0) + 1;
    a.failedAttempts = 0; a.lockUntil = null;
    logEvent(data, "Super Admin", `Reissued a PIN for admin: ${a.name}`);
  } else {
    a = { id: genId("a"), name: adminName, pinHash: await bcrypt.hash(newPin, 10),
      mustChangePin: true, recoveryCodeHash: null, tokenVersion: 0, failedAttempts: 0, lockUntil: null, lastActiveAt: null };
    data.admins.push(a);
    logEvent(data, "Super Admin", `Added a new admin: ${adminName}`);
  }
  ensureMemberForAdmin(data, adminName);
  await ref.set(data);
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
  const data = snap.exists ? snap.data() : defaultFlight();
  await flights.doc(newName).set(data);
  await oldRef.delete();

  await setFlightNames(names.map(n => n === oldName ? newName : n));
  res.json({ success: true });
});

app.post("/api/owner/flights/:name/revoke", ownerMiddleware, async (req, res) => {
  const name = req.params.name;
  const names = await getFlightNames();
  if(!names.includes(name)) return res.status(404).json({ message: "Flight not found." });
  const { ref, data } = await getOrCreateFlight(name);

  const adminName = String(req.body.adminName || "").trim();
  const a = findAdmin(data, adminName);
  if(!a) return res.status(404).json({ message: "No admin with that name on this flight." });

  a.pinHash = null;
  a.recoveryCodeHash = null;
  a.mustChangePin = false;
  a.tokenVersion = (a.tokenVersion || 0) + 1;
  a.failedAttempts = 0; a.lockUntil = null;
  logEvent(data, "Super Admin", `Revoked access for admin: ${a.name}`);
  await ref.set(data);
  res.json({ success: true });
});

// Super Admin can wipe a flight's data without needing to log in as its admin.
// Admins and their PINs are kept — only members/games/payments/stock are cleared.
app.post("/api/owner/flights/:name/erase-data", ownerMiddleware, async (req, res) => {
  const name = req.params.name;
  const names = await getFlightNames();
  if(!names.includes(name)) return res.status(404).json({ message: "Flight not found." });
  const { ref, data } = await getOrCreateFlight(name);
  const fresh = { ...defaultFlight(), admins: data.admins, auditLog: data.auditLog || [],
    tubePriceFils: data.tubePriceFils, shuttlesPerTube: data.shuttlesPerTube };
  logEvent(fresh, "Super Admin", "Erased all members, games, payments and stock for this flight");
  await ref.set(fresh);
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
    if(!payload.flightName || !payload.adminId) throw new Error("bad token");
    req.flightName = payload.flightName;
    req.adminId = payload.adminId;
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
  const a = findAdminById(data, req.adminId);
  if(!a || (a.tokenVersion || 0) !== req.tokenVersion){
    res.status(401).json({ message: "Your session was ended — please sign in again." });
    return null;
  }
  return { ref, data, admin: a };
}

app.get("/api/flight", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  res.json(publicFlight(req.flightName, ctx.data, ctx.admin.id));
});

app.post("/api/flight/settings", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const { tubePriceFils, shuttlesPerTube, addTubes, setStockExact } = req.body;
  if(!(tubePriceFils > 0)) return res.status(400).json({ message: "Enter a tube price greater than zero." });
  if(!(shuttlesPerTube > 0)) return res.status(400).json({ message: "Enter how many shuttles are in a tube." });
  data.tubePriceFils = Math.round(tubePriceFils);
  data.shuttlesPerTube = Math.round(shuttlesPerTube);

  let stockNote = "";
  if(setStockExact !== undefined && setStockExact !== null && String(setStockExact).trim() !== ""){
    data.shuttlesInStock = Math.max(0, Math.round(Number(setStockExact)));
    stockNote = `, stock set to ${data.shuttlesInStock}`;
  } else {
    const tubesToAdd = Math.max(0, Math.round(Number(addTubes) || 0));
    if(tubesToAdd > 0){
      data.shuttlesInStock = (data.shuttlesInStock || 0) + tubesToAdd * data.shuttlesPerTube;
      stockNote = `, added ${tubesToAdd} tube(s)`;
    }
  }
  logEvent(data, adm.name, `Updated settings (tube price BHD ${(data.tubePriceFils/1000).toFixed(3)}, ${data.shuttlesPerTube}/tube${stockNote})`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.post("/api/flight/pin", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const { oldPin, newPin } = req.body;
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });
  const ok = await bcrypt.compare(oldPin || "", adm.pinHash);
  if(!ok) return res.status(401).json({ message: "Current PIN is incorrect." });
  adm.pinHash = await bcrypt.hash(newPin, 10);
  adm.mustChangePin = false;
  adm.tokenVersion = (adm.tokenVersion || 0) + 1;
  logEvent(data, adm.name, "Changed their own PIN");
  await ref.set(data);
  res.json({ success: true });
});

app.post("/api/flight/pin/confirm-change", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  if(!adm.mustChangePin) return res.status(400).json({ message: "No PIN change is required right now." });
  const { newPin } = req.body;
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });
  adm.pinHash = await bcrypt.hash(newPin, 10);
  adm.mustChangePin = false;
  adm.tokenVersion = (adm.tokenVersion || 0) + 1;
  logEvent(data, adm.name, "Set their own PIN for the first time");
  await ref.set(data);
  res.json({ success: true });
});

app.post("/api/flight/recovery-code", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const code = String(req.body.recoveryCode || "").trim();
  if(code.length < 4) return res.status(400).json({ message: "Recovery code should be at least 4 characters." });
  adm.recoveryCodeHash = await bcrypt.hash(code, 10);
  logEvent(data, adm.name, "Set their recovery code");
  await ref.set(data);
  res.json({ success: true });
});

/* --- Admins (self-service, any signed-in admin) --- */
app.post("/api/flight/admins", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const name = String(req.body.name || "").trim();
  const pin = String(req.body.pin || "").trim();
  if(!name) return res.status(400).json({ message: "Enter a name." });
  if(!/^\d{4,6}$/.test(pin)) return res.status(400).json({ message: "PIN must be 4–6 digits." });
  if(findAdmin(data, name)) return res.status(409).json({ message: "An admin with that name already exists." });

  const newAdmin = { id: genId("a"), name, pinHash: await bcrypt.hash(pin, 10),
    mustChangePin: true, recoveryCodeHash: null, tokenVersion: 0, failedAttempts: 0, lockUntil: null, lastActiveAt: null };
  data.admins.push(newAdmin);
  ensureMemberForAdmin(data, name);
  logEvent(data, adm.name, `Added a new admin: ${name}`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.delete("/api/flight/admins/:id", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  if(data.admins.length <= 1) return res.status(409).json({ message: "You can't remove the only admin left on this flight." });
  const target = findAdminById(data, req.params.id);
  if(!target) return res.status(404).json({ message: "Admin not found." });
  data.admins = data.admins.filter(a => a.id !== req.params.id);
  logEvent(data, adm.name, `Removed admin: ${target.name}`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.post("/api/flight/stock/reset", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  data.shuttlesInStock = 0;
  logEvent(data, adm.name, "Reset stock to 0");
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.delete("/api/flight/members/clear-all", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const count = data.members.length;
  data.members = [];
  logEvent(data, adm.name, `Removed all members (${count})`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.delete("/api/flight/sessions/clear-all", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const count = data.sessions.length;
  data.sessions = [];
  data.paid = {};
  logEvent(data, adm.name, `Cleared all games (${count})`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.post("/api/members", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
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
  logEvent(data, adm.name, `Added member: ${name}`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.patch("/api/members/:id/toggle", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const m = data.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  m.active = !m.active;
  logEvent(data, adm.name, `${m.active ? "Activated" : "Deactivated"} member: ${m.name}`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.patch("/api/members/:id", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const { name, phone } = req.body;
  const m = data.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  const oldName = m.name;
  if(name !== undefined){
    const n = String(name).trim();
    if(!n) return res.status(400).json({ message: "Name required." });
    m.name = n;
  }
  if(phone !== undefined) m.phone = String(phone).trim();
  if(!m.publicToken) m.publicToken = genToken();
  logEvent(data, adm.name, `Edited member: ${oldName}${m.name !== oldName ? ` → ${m.name}` : ""}`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.delete("/api/members/:id", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const m = data.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  const owed = outstandingFils(data, m.id);
  if(owed > 0) return res.status(409).json({ message: `${m.name} still owes BHD ${(owed/1000).toFixed(3)} — settle that first.` });
  data.members = data.members.filter(x => x.id !== req.params.id);
  logEvent(data, adm.name, `Deleted member: ${m.name}`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.post("/api/sessions", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const { date, shuttlesUsed, presentIds } = req.body;
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
    createdBy: adm.name,
    createdAt: new Date().toISOString()
  });
  data.shuttlesInStock = (data.shuttlesInStock || 0) - shuttlesUsed;
  logEvent(data, adm.name, `Saved game ${date}: ${shuttlesUsed} shuttles used, ${presentIds.length} present`);

  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.delete("/api/sessions/:id", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const session = data.sessions.find(s => s.id === req.params.id);
  data.sessions = data.sessions.filter(s => s.id !== req.params.id);
  Object.keys(data.paid).forEach(k => { if(k.startsWith(req.params.id + "_")) delete data.paid[k]; });
  if(session){
    data.shuttlesInStock = (data.shuttlesInStock || 0) + session.shuttlesUsed;
    logEvent(data, adm.name, `Deleted game ${session.date}`);
  }
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.post("/api/payments/:sessionId/:memberId/pay-partial", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const amountFils = Math.round(Number(req.body.amountFils) || 0);
  if(amountFils <= 0) return res.status(400).json({ message: "Enter an amount greater than zero." });
  const key = `${req.params.sessionId}_${req.params.memberId}`;
  const session = data.sessions.find(s => s.id === req.params.sessionId);
  const share = session?.shares[req.params.memberId] || 0;
  const already = paidAmountFor(data, key, share);
  data.paid[key] = Math.min(share, already + amountFils);
  const memberName = memberNameById(data.members, req.params.memberId);
  logEvent(data, adm.name, `Recorded payment: BHD ${(amountFils/1000).toFixed(3)} from ${memberName}${session ? ` for ${session.date}` : ""}`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.post("/api/payments/:memberId/settle-all", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  data.sessions.forEach(s => { if(s.shares[req.params.memberId]) data.paid[`${s.id}_${req.params.memberId}`] = s.shares[req.params.memberId]; });
  const memberName = memberNameById(data.members, req.params.memberId);
  logEvent(data, adm.name, `Settled all outstanding for ${memberName}`);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data, adm.id));
});

app.delete("/api/flight/reset", async (req, res) => {
  const ctx = await loadFlightChecked(req, res); if(!ctx) return;
  const { ref, data, admin: adm } = ctx;
  const fresh = { ...defaultFlight(), admins: data.admins, auditLog: data.auditLog || [],
    tubePriceFils: data.tubePriceFils, shuttlesPerTube: data.shuttlesPerTube };
  logEvent(fresh, adm.name, "Erased all members, games, payments and stock for this flight");
  await ref.set(fresh);
  res.json(publicFlight(req.flightName, fresh, adm.id));
});

app.get(/^(?!\/api).*/, (req, res) => res.sendFile(path.join(__dirname, "public/index.html")));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Shuttle server running on port ${PORT}`));
