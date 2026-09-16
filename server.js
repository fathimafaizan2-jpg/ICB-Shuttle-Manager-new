import express from "express";
import admin from "firebase-admin";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const JWT_SECRET = process.env.JWT_SECRET;
const FLIGHT_NAMES = ["Premier Flight","Flight 1","Flight 2","Flight 3","Flight 4A","Flight 4B"];

/* ===================================================================
   DATABASE — Firestore
   One document per flight, in the "flights" collection, doc ID = the
   flight name. No query in this file ever reads more than one doc at
   a time, so a token for one flight can never surface another's data.
   =================================================================== */
   const serviceAccount = JSON.parse(
     Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, "base64").toString("utf8")
   );

   admin.initializeApp({
     credential: admin.credential.cert(serviceAccount)
   });
const db = admin.firestore();
const flights = db.collection("flights");

const DEFAULT_FLIGHT = {
  pinHash: null, adminName: "", tubePriceFils: 14500, shuttlesPerTube: 12,
  members: [], sessions: [], paid: {}
};

async function getOrCreateFlight(name){
  const ref = flights.doc(name);
  const snap = await ref.get();
  if(!snap.exists){
    await ref.set(DEFAULT_FLIGHT);
    return { ref, data: { ...DEFAULT_FLIGHT } };
  }
  return { ref, data: snap.data() };
}

/* ===================================================================
   CORE CALCULATION — same rules as before, authoritative on the server.
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
function outstandingFils(data, memberId){
  return data.sessions.reduce((sum,s) => {
    const share = s.shares[memberId];
    if(!share) return sum;
    return data.paid[`${s.id}_${memberId}`] ? sum : sum + share;
  }, 0);
}
function publicFlight(name, data){
  const { pinHash, ...rest } = data;
  return { flightName: name, ...rest, hasPin: !!pinHash };
}

/* ===================================================================
   AUTH
   =================================================================== */
function authMiddleware(req, res, next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if(!token) return res.status(401).json({ message: "Not signed in." });
  try{
    req.flightName = jwt.verify(token, JWT_SECRET).flightName;
    next();
  }catch{
    res.status(401).json({ message: "Session expired — please sign in again." });
  }
}

app.get("/api/flights", (req, res) => res.json(FLIGHT_NAMES));

app.post("/api/login", async (req, res) => {
  const { flightName, pin } = req.body;
  if(!FLIGHT_NAMES.includes(flightName)) return res.status(400).json({ message: "Unknown flight." });
  if(!/^\d{4,6}$/.test(pin || "")) return res.status(400).json({ message: "PIN must be 4–6 digits." });

  const { ref, data } = await getOrCreateFlight(flightName);

  if(!data.pinHash){
    data.pinHash = await bcrypt.hash(pin, 10);
    await ref.set(data);
  }else{
    const ok = await bcrypt.compare(pin, data.pinHash);
    if(!ok) return res.status(401).json({ message: "Incorrect PIN." });
  }

  const token = jwt.sign({ flightName }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, flight: publicFlight(flightName, data) });
});

app.use("/api", authMiddleware);

app.get("/api/flight", async (req, res) => {
  const { data } = await getOrCreateFlight(req.flightName);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/flight/settings", async (req, res) => {
  const { adminName, tubePriceFils, shuttlesPerTube } = req.body;
  if(!(tubePriceFils > 0)) return res.status(400).json({ message: "Enter a tube price greater than zero." });
  if(!(shuttlesPerTube > 0)) return res.status(400).json({ message: "Enter how many shuttles are in a tube." });
  const { ref, data } = await getOrCreateFlight(req.flightName);
  data.adminName = String(adminName || "").trim();
  data.tubePriceFils = Math.round(tubePriceFils);
  data.shuttlesPerTube = Math.round(shuttlesPerTube);
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/flight/pin", async (req, res) => {
  const { oldPin, newPin } = req.body;
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });
  const { ref, data } = await getOrCreateFlight(req.flightName);
  const ok = await bcrypt.compare(oldPin || "", data.pinHash);
  if(!ok) return res.status(401).json({ message: "Current PIN is incorrect." });
  data.pinHash = await bcrypt.hash(newPin, 10);
  await ref.set(data);
  res.json({ success: true });
});

app.post("/api/members", async (req, res) => {
  const name = String(req.body.name || "").trim();
  if(!name) return res.status(400).json({ message: "Type a name first." });
  const { ref, data } = await getOrCreateFlight(req.flightName);
  if(data.members.some(m => m.name.toLowerCase() === name.toLowerCase())){
    return res.status(409).json({ message: "That name is already in this flight." });
  }
  data.members.push({ id: "m" + Date.now().toString(36) + Math.random().toString(36).slice(2,6), name, active:true });
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.patch("/api/members/:id/toggle", async (req, res) => {
  const { ref, data } = await getOrCreateFlight(req.flightName);
  const m = data.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  m.active = !m.active;
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.patch("/api/members/:id/rename", async (req, res) => {
  const name = String(req.body.name || "").trim();
  if(!name) return res.status(400).json({ message: "Name required." });
  const { ref, data } = await getOrCreateFlight(req.flightName);
  const m = data.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  m.name = name;
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/sessions", async (req, res) => {
  const { date, shuttlesUsed, presentIds } = req.body;
  if(!date) return res.status(400).json({ message: "Pick the game date." });
  if(!Number.isInteger(shuttlesUsed) || shuttlesUsed <= 0) return res.status(400).json({ message: "Enter how many shuttles were used." });
  if(!Array.isArray(presentIds) || !presentIds.length) return res.status(400).json({ message: "Mark at least one player present." });

  const { ref, data } = await getOrCreateFlight(req.flightName);
  const total = dayCostFils(data.tubePriceFils, data.shuttlesPerTube, shuttlesUsed);
  const shares = splitShares(total, presentIds);

  data.sessions.push({
    id: "s" + Date.now().toString(36) + Math.random().toString(36).slice(2,6),
    date, shuttlesUsed, presentIds, totalCostFils: total, shares,
    createdAt: new Date().toISOString()
  });
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.delete("/api/sessions/:id", async (req, res) => {
  const { ref, data } = await getOrCreateFlight(req.flightName);
  data.sessions = data.sessions.filter(s => s.id !== req.params.id);
  Object.keys(data.paid).forEach(k => { if(k.startsWith(req.params.id + "_")) delete data.paid[k]; });
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/payments/:sessionId/:memberId/pay", async (req, res) => {
  const { ref, data } = await getOrCreateFlight(req.flightName);
  data.paid[`${req.params.sessionId}_${req.params.memberId}`] = true;
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.post("/api/payments/:memberId/settle-all", async (req, res) => {
  const { ref, data } = await getOrCreateFlight(req.flightName);
  data.sessions.forEach(s => { if(s.shares[req.params.memberId]) data.paid[`${s.id}_${req.params.memberId}`] = true; });
  await ref.set(data);
  res.json(publicFlight(req.flightName, data));
});

app.delete("/api/flight/reset", async (req, res) => {
  const { ref, data } = await getOrCreateFlight(req.flightName);
  const keepPin = data.pinHash, keepAdmin = data.adminName, keepPrice = data.tubePriceFils, keepPerTube = data.shuttlesPerTube;
  const fresh = { ...DEFAULT_FLIGHT, pinHash: keepPin, adminName: keepAdmin, tubePriceFils: keepPrice, shuttlesPerTube: keepPerTube };
  await ref.set(fresh);
  res.json(publicFlight(req.flightName, fresh));
});

app.get(/^(?!\/api).*/, (req, res) => res.sendFile(path.join(__dirname, "public/index.html")));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Shuttle server running on port ${PORT}`));
