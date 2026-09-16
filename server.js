import express from "express";
import mongoose from "mongoose";
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
   DATABASE
   One document per flight. Nothing in one flight's document ever
   references another — there is no query capable of crossing flights.
   =================================================================== */
await mongoose.connect(process.env.MONGODB_URI);

const flightSchema = new mongoose.Schema({
  flightName: { type: String, required: true, unique: true },
  pinHash: { type: String, default: null },
  adminName: { type: String, default: "" },
  tubePriceFils: { type: Number, default: 14500 },
  shuttlesPerTube: { type: Number, default: 12 },
  members: [{ id: String, name: String, active: { type: Boolean, default: true } }],
  sessions: [{
    id: String, date: String, shuttlesUsed: Number, presentIds: [String],
    totalCostFils: Number, shares: mongoose.Schema.Types.Mixed, createdAt: String
  }],
  paid: { type: mongoose.Schema.Types.Mixed, default: {} }
});
const Flight = mongoose.model("Flight", flightSchema);

async function getOrCreateFlight(name){
  let fl = await Flight.findOne({ flightName: name });
  if(!fl) fl = await Flight.create({ flightName: name });
  return fl;
}

/* ===================================================================
   CORE CALCULATION — authoritative on the server, never trusted from
   the client. Same rules as before: whole fils, remainder handed out
   one at a time so shares always sum to exactly the day cost.
   =================================================================== */
const FILS = 1000;
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
function outstandingFils(fl, memberId){
  return fl.sessions.reduce((sum,s) => {
    const share = s.shares[memberId];
    if(!share) return sum;
    return fl.paid[`${s.id}_${memberId}`] ? sum : sum + share;
  }, 0);
}

function publicFlight(fl){
  // Never send the PIN hash to the browser.
  const { pinHash, ...rest } = fl.toObject();
  return { ...rest, hasPin: !!pinHash };
}

/* ===================================================================
   AUTH
   =================================================================== */
function authMiddleware(req, res, next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if(!token) return res.status(401).json({ message: "Not signed in." });
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.flightName = payload.flightName;
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

  const fl = await getOrCreateFlight(flightName);

  if(!fl.pinHash){
    fl.pinHash = await bcrypt.hash(pin, 10);
    await fl.save();
  }else{
    const ok = await bcrypt.compare(pin, fl.pinHash);
    if(!ok) return res.status(401).json({ message: "Incorrect PIN." });
  }

  const token = jwt.sign({ flightName }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, flight: publicFlight(fl) });
});

/* Every route below this line requires a valid token, and every query
   is filtered to req.flightName — there is no route that can return
   another flight's document. */
app.use("/api", authMiddleware);

app.get("/api/flight", async (req, res) => {
  const fl = await getOrCreateFlight(req.flightName);
  res.json(publicFlight(fl));
});

app.post("/api/flight/settings", async (req, res) => {
  const { adminName, tubePriceFils, shuttlesPerTube } = req.body;
  if(!(tubePriceFils > 0)) return res.status(400).json({ message: "Enter a tube price greater than zero." });
  if(!(shuttlesPerTube > 0)) return res.status(400).json({ message: "Enter how many shuttles are in a tube." });
  const fl = await getOrCreateFlight(req.flightName);
  fl.adminName = String(adminName || "").trim();
  fl.tubePriceFils = Math.round(tubePriceFils);
  fl.shuttlesPerTube = Math.round(shuttlesPerTube);
  await fl.save();
  res.json(publicFlight(fl));
});

app.post("/api/flight/pin", async (req, res) => {
  const { oldPin, newPin } = req.body;
  if(!/^\d{4,6}$/.test(newPin || "")) return res.status(400).json({ message: "New PIN must be 4–6 digits." });
  const fl = await getOrCreateFlight(req.flightName);
  const ok = await bcrypt.compare(oldPin || "", fl.pinHash);
  if(!ok) return res.status(401).json({ message: "Current PIN is incorrect." });
  fl.pinHash = await bcrypt.hash(newPin, 10);
  await fl.save();
  res.json({ success: true });
});

app.post("/api/members", async (req, res) => {
  const name = String(req.body.name || "").trim();
  if(!name) return res.status(400).json({ message: "Type a name first." });
  const fl = await getOrCreateFlight(req.flightName);
  if(fl.members.some(m => m.name.toLowerCase() === name.toLowerCase())){
    return res.status(409).json({ message: "That name is already in this flight." });
  }
  fl.members.push({ id: "m" + Date.now().toString(36) + Math.random().toString(36).slice(2,6), name, active:true });
  await fl.save();
  res.json(publicFlight(fl));
});

app.patch("/api/members/:id/toggle", async (req, res) => {
  const fl = await getOrCreateFlight(req.flightName);
  const m = fl.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  m.active = !m.active;
  await fl.save();
  res.json(publicFlight(fl));
});

app.patch("/api/members/:id/rename", async (req, res) => {
  const name = String(req.body.name || "").trim();
  if(!name) return res.status(400).json({ message: "Name required." });
  const fl = await getOrCreateFlight(req.flightName);
  const m = fl.members.find(x => x.id === req.params.id);
  if(!m) return res.status(404).json({ message: "Member not found." });
  m.name = name;
  await fl.save();
  res.json(publicFlight(fl));
});

app.post("/api/sessions", async (req, res) => {
  const { date, shuttlesUsed, presentIds } = req.body;
  if(!date) return res.status(400).json({ message: "Pick the game date." });
  if(!Number.isInteger(shuttlesUsed) || shuttlesUsed <= 0) return res.status(400).json({ message: "Enter how many shuttles were used." });
  if(!Array.isArray(presentIds) || !presentIds.length) return res.status(400).json({ message: "Mark at least one player present." });

  const fl = await getOrCreateFlight(req.flightName);
  const total = dayCostFils(fl.tubePriceFils, fl.shuttlesPerTube, shuttlesUsed);
  const shares = splitShares(total, presentIds);

  fl.sessions.push({
    id: "s" + Date.now().toString(36) + Math.random().toString(36).slice(2,6),
    date, shuttlesUsed, presentIds, totalCostFils: total, shares,
    createdAt: new Date().toISOString()
  });
  await fl.save();
  res.json(publicFlight(fl));
});

app.delete("/api/sessions/:id", async (req, res) => {
  const fl = await getOrCreateFlight(req.flightName);
  fl.sessions = fl.sessions.filter(s => s.id !== req.params.id);
  const paid = { ...fl.paid };
  Object.keys(paid).forEach(k => { if(k.startsWith(req.params.id + "_")) delete paid[k]; });
  fl.paid = paid;
  await fl.save();
  res.json(publicFlight(fl));
});

app.post("/api/payments/:sessionId/:memberId/pay", async (req, res) => {
  const fl = await getOrCreateFlight(req.flightName);
  fl.paid = { ...fl.paid, [`${req.params.sessionId}_${req.params.memberId}`]: true };
  await fl.save();
  res.json(publicFlight(fl));
});

app.post("/api/payments/:memberId/settle-all", async (req, res) => {
  const fl = await getOrCreateFlight(req.flightName);
  const paid = { ...fl.paid };
  fl.sessions.forEach(s => { if(s.shares[req.params.memberId]) paid[`${s.id}_${req.params.memberId}`] = true; });
  fl.paid = paid;
  await fl.save();
  res.json(publicFlight(fl));
});

app.delete("/api/flight/reset", async (req, res) => {
  const fl = await getOrCreateFlight(req.flightName);
  fl.members = []; fl.sessions = []; fl.paid = {};
  await fl.save();
  res.json(publicFlight(fl));
});

// Any non-API route falls back to the frontend (single-page app).
app.get(/^(?!\/api).*/, (req, res) => res.sendFile(path.join(__dirname, "public/index.html")));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Shuttle server running on port ${PORT}`));
