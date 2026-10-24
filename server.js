/*
TRAVELSHIELD — AI Powered Smart Tourist Safety System
Single-file full-stack app inspired by the uploaded SafeYatra Nexus report.

RUN:
  1) Install Node.js 18+.
  2) Create a folder and save this file as server.js
  3) In that folder:
       npm init -y
       npm i express mongoose bcryptjs jsonwebtoken dotenv
       node server.js
  4) Open http://localhost:5000

OPTIONAL MONGODB:
  Create .env:
    PORT=5000
    MONGODB_URI=mongodb+srv://USER:PASSWORD@CLUSTER.mongodb.net/travelshield
    JWT_SECRET=change-this-secret

If MONGODB_URI is missing/unavailable, the app automatically uses a local
data/travelshield.json store, so the project still runs in VS Code.

DEPLOY:
  Render/Railway/Fly/etc. can run:
    Build: npm install
    Start: node server.js
  Set MONGODB_URI and JWT_SECRET as environment variables for persistent cloud data.

IMPORTANT:
  This is a major-project prototype. Browser geolocation, risk scoring and
  incident workflows are functional. Real SMS/GSM, production blockchain,
  TensorFlow Lite models, and emergency-service dispatch require external
  hardware/API integrations and are not falsely represented as live services.
*/

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`TravelShield running on port ${PORT}`);
});
const JWT_SECRET = process.env.JWT_SECRET || "travelshield-development-secret";

app.use(express.json({ limit: "1mb" }));

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "travelshield.json");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readStore() {
  try {
    if (!fs.existsSync(DATA_FILE)) return { users: [], trips: [], incidents: [], locations: [] };
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {
    return { users: [], trips: [], incidents: [], locations: [] };
  }
}
function writeStore(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let mongoReady = false;
let User, Trip, Incident, Location;

async function connectMongo() {
  if (!process.env.MONGODB_URI) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    mongoReady = true;

    const userSchema = new mongoose.Schema({
      fullName: { type: String, required: true },
      email: { type: String, unique: true, required: true, lowercase: true },
      passwordHash: { type: String, required: true },
      phone: String,
      emergencyContact: String,
      bloodGroup: String,
      allergies: String,
      touristId: { type: String, unique: true },
      createdAt: { type: Date, default: Date.now }
    });
    const tripSchema = new mongoose.Schema({
      userId: String, destination: String, startDate: String, endDate: String,
      nationality: String, passport: String, emergencyContact: String,
      riskLevel: String, createdAt: { type: Date, default: Date.now }
    });
    const incidentSchema = new mongoose.Schema({
      userId: String, touristId: String, type: String, message: String,
      latitude: Number, longitude: Number, status: String,
      createdAt: { type: Date, default: Date.now }
    });
    const locationSchema = new mongoose.Schema({
      userId: String, latitude: Number, longitude: Number,
      riskLevel: String, createdAt: { type: Date, default: Date.now }
    });
    User = mongoose.models.TSUser || mongoose.model("TSUser", userSchema);
    Trip = mongoose.models.TSTrip || mongoose.model("TSTrip", tripSchema);
    Incident = mongoose.models.TSIncident || mongoose.model("TSIncident", incidentSchema);
    Location = mongoose.models.TSLocation || mongoose.model("TSLocation", locationSchema);
    console.log("MongoDB connected.");
  } catch (e) {
    console.log("MongoDB unavailable; using local JSON store.");
  }
}

function id(prefix = "") {
  return prefix + crypto.randomBytes(8).toString("hex");
}
function touristId() {
  const d = new Date().toISOString().slice(0,10).replace(/-/g,"");
  return `TID-${d}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
}
function tokenFor(user) {
  return jwt.sign({ id: String(user._id || user.id), email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "Authentication required" });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid or expired token" }); }
}

function riskFromPoint(lat, lng) {
  // Demonstration geofencing/risk model. Replace these sample circles with
  // authority-provided zone polygons/data in the production version.
  const zones = [
    { name:"Restricted Demo Zone", lat:17.3850, lng:78.4867, radius:.012, level:"HIGH" },
    { name:"Caution Demo Zone", lat:17.4065, lng:78.4772, radius:.020, level:"MODERATE" }
  ];
  for (const z of zones) {
    const distance = Math.hypot(lat-z.lat, lng-z.lng);
    if (distance <= z.radius) return { level:z.level, zone:z.name };
  }
  return { level:"SAFE", zone:"Safe Zone" };
}

app.get("/api/health", (req,res)=>res.json({ ok:true, database:mongoReady?"mongodb":"local-json", time:new Date().toISOString() }));

app.post("/api/auth/register", async (req,res)=>{
  try {
    const { fullName,email,password,phone,emergencyContact,bloodGroup,allergies } = req.body;
    if (!fullName || !email || !password) return res.status(400).json({error:"Name, email and password are required."});
    const normalized = email.trim().toLowerCase();
    if (mongoReady) {
      if (await User.findOne({email:normalized})) return res.status(409).json({error:"Email already registered."});
      const u = await User.create({
        fullName:fullName.trim(), email:normalized,
        passwordHash:await bcrypt.hash(password,12), phone, emergencyContact,
        bloodGroup, allergies, touristId:touristId()
      });
      return res.json({message:"Registration successful", token:tokenFor(u), user:{id:String(u._id),fullName:u.fullName,email:u.email,touristId:u.touristId}});
    }
    const s=readStore();
    if(s.users.some(u=>u.email===normalized)) return res.status(409).json({error:"Email already registered."});
    const u={id:id("usr_"),fullName:fullName.trim(),email:normalized,passwordHash:await bcrypt.hash(password,12),phone,emergencyContact,bloodGroup,allergies,touristId:touristId(),createdAt:new Date().toISOString()};
    s.users.push(u); writeStore(s);
    res.json({message:"Registration successful",token:tokenFor(u),user:{id:u.id,fullName:u.fullName,email:u.email,touristId:u.touristId}});
  } catch(e){res.status(500).json({error:"Registration failed."});}
});

app.post("/api/auth/login", async (req,res)=>{
  try {
    const email=(req.body.email||"").trim().toLowerCase(), password=req.body.password||"";
    let u;
    if(mongoReady) u=await User.findOne({email});
    else u=readStore().users.find(x=>x.email===email);
    if(!u || !(await bcrypt.compare(password,u.passwordHash))) return res.status(401).json({error:"Invalid email or password."});
    res.json({message:"Login successful",token:tokenFor(u),user:{id:String(u._id||u.id),fullName:u.fullName,email:u.email,phone:u.phone,emergencyContact:u.emergencyContact,bloodGroup:u.bloodGroup,allergies:u.allergies,touristId:u.touristId}});
  } catch(e){res.status(500).json({error:"Login failed."});}
});

app.get("/api/me",auth,async(req,res)=>{
  if(mongoReady){ const u=await User.findById(req.user.id).lean(); if(!u)return res.status(404).json({error:"User not found"}); delete u.passwordHash; return res.json(u); }
  const u=readStore().users.find(x=>x.id===req.user.id); if(!u)return res.status(404).json({error:"User not found"}); const out={...u};delete out.passwordHash;res.json(out);
});

app.post("/api/trips",auth,async(req,res)=>{
  const {destination,startDate,endDate,nationality,passport,emergencyContact}=req.body;
  if(!destination||!startDate||!endDate||!nationality||!passport||!emergencyContact)return res.status(400).json({error:"Please complete all trip fields."});
  const trip={userId:req.user.id,destination,startDate,endDate,nationality,passport,emergencyContact,riskLevel:"MONITORING ACTIVE",createdAt:new Date().toISOString()};
  if(mongoReady){const t=await Trip.create(trip);return res.json(t);}
  const s=readStore();trip.id=id("trip_");s.trips.push(trip);writeStore(s);res.json(trip);
});

app.get("/api/trips",auth,async(req,res)=>{
  if(mongoReady)return res.json(await Trip.find({userId:req.user.id}).sort({createdAt:-1}).lean());
  res.json(readStore().trips.filter(t=>t.userId===req.user.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)));
});

app.post("/api/location",auth,async(req,res)=>{
  const {latitude,longitude}=req.body;
  if(!Number.isFinite(latitude)||!Number.isFinite(longitude))return res.status(400).json({error:"Valid coordinates required."});
  const risk=riskFromPoint(latitude,longitude);
  const row={userId:req.user.id,latitude,longitude,...risk,createdAt:new Date().toISOString()};
  if(mongoReady){await Location.create(row);return res.json(risk);}
  const s=readStore();row.id=id("loc_");s.locations.push(row);s.locations=s.locations.slice(-2000);writeStore(s);res.json(risk);
});

app.get("/api/locations/latest",auth,async(req,res)=>{
  if(mongoReady){const x=await Location.find({userId:req.user.id}).sort({createdAt:-1}).limit(30).lean();return res.json(x);}
  res.json(readStore().locations.filter(x=>x.userId===req.user.id).slice(-30).reverse());
});

app.post("/api/incidents",auth,async(req,res)=>{
  const {type="SOS",message="",latitude,longitude}=req.body;
  let u;
  if(mongoReady)u=await User.findById(req.user.id).lean();
  else u=readStore().users.find(x=>x.id===req.user.id);
  const incident={userId:req.user.id,touristId:u?.touristId||"UNKNOWN",type,message,latitude,longitude,status:"OPEN",createdAt:new Date().toISOString()};
  if(mongoReady){const x=await Incident.create(incident);return res.json({message:"Emergency incident created",incident:x});}
  const s=readStore();incident.id=id("inc_");s.incidents.push(incident);writeStore(s);res.json({message:"Emergency incident created",incident});
});

app.get("/api/incidents",auth,async(req,res)=>{
  if(mongoReady)return res.json(await Incident.find({userId:req.user.id}).sort({createdAt:-1}).limit(50).lean());
  res.json(readStore().incidents.filter(x=>x.userId===req.user.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).slice(0,50));
});

// Admin demo endpoint. In a real deployment, use a dedicated admin role + RBAC.
app.get("/api/admin/overview",auth,async(req,res)=>{
  if(mongoReady){
    const [users,incidents,locations]=await Promise.all([User.countDocuments(),Incident.countDocuments({status:"OPEN"}),Location.find().sort({createdAt:-1}).limit(100).lean()]);
    return res.json({users,openIncidents:incidents,locations});
  }
  const s=readStore();res.json({users:s.users.length,openIncidents:s.incidents.filter(i=>i.status==="OPEN").length,locations:s.locations.slice(-100).reverse()});
});

app.get("/sw.js",(req,res)=>{
  res.type("application/javascript").send(`
const CACHE="travelshield-v1";
self.addEventListener("install",e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(["/"]))));
self.addEventListener("fetch",e=>{
  if(e.request.method!=="GET") return;
  e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));
});
`);
});

const HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#07111f">
<title>TravelShield — Smart Tourist Safety</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg:#06101d;--panel:rgba(13,29,48,.78);--line:rgba(148,163,184,.16);--text:#eaf2ff;--muted:#8fa3bc;--cyan:#39d5ff;--blue:#4d7cff;--green:#2fe2a0;--yellow:#ffc857;--red:#ff5571;--shadow:0 25px 80px rgba(0,0,0,.32)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Inter,sans-serif;background:radial-gradient(circle at 15% 10%,#0e3150 0,transparent 32%),radial-gradient(circle at 90% 0,#14255d 0,transparent 28%),var(--bg);color:var(--text)}
button,input,select,textarea{font:inherit}button{cursor:pointer;border:0}.hidden{display:none!important}
.container{max-width:1400px;margin:auto;padding:28px}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:13px}.logo{width:45px;height:45px;border-radius:15px;background:linear-gradient(135deg,var(--cyan),var(--blue));display:grid;place-items:center;box-shadow:0 0 35px rgba(57,213,255,.25)}.brand b{font-family:"Space Grotesk";font-size:21px}.brand span{display:block;color:var(--muted);font-size:11px;margin-top:3px;letter-spacing:.13em;text-transform:uppercase}
.pill{border:1px solid var(--line);background:rgba(255,255,255,.04);border-radius:999px;padding:9px 13px;color:#c9d7ea;font-size:12px}
.grid{display:grid;grid-template-columns:280px 1fr;gap:22px}.side,.card{border:1px solid var(--line);background:var(--panel);backdrop-filter:blur(20px);box-shadow:var(--shadow);border-radius:22px}.side{padding:16px;height:calc(100vh - 115px);position:sticky;top:20px}.nav{display:flex;flex-direction:column;gap:7px}.nav button{background:transparent;color:#9eb0c7;text-align:left;padding:13px 14px;border-radius:13px}.nav button.active,.nav button:hover{background:rgba(57,213,255,.09);color:white}.nav small{color:#61758d;padding:15px 12px 7px;text-transform:uppercase;letter-spacing:.12em}
.main{min-width:0}.hero{padding:28px;display:flex;justify-content:space-between;gap:20px;align-items:flex-start;margin-bottom:18px;background:linear-gradient(135deg,rgba(22,53,83,.86),rgba(8,24,40,.75));overflow:hidden;position:relative}.hero:after{content:"";position:absolute;width:300px;height:300px;border-radius:50%;right:-100px;top:-150px;background:rgba(57,213,255,.12);filter:blur(25px)}h1,h2,h3{font-family:"Space Grotesk";margin:0}h1{font-size:clamp(27px,4vw,46px);line-height:1.05;max-width:720px}.sub{color:var(--muted);line-height:1.7;max-width:720px;margin-top:12px}.status{display:flex;align-items:center;gap:8px;color:#b8c7da;font-size:12px}.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 14px var(--green)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}.stat{padding:20px}.stat .num{font-size:28px;font-family:"Space Grotesk";font-weight:700;margin:8px 0}.stat p{margin:0;color:var(--muted);font-size:12px}.cards{display:grid;grid-template-columns:1.6fr 1fr;gap:18px}.card{padding:20px}.card h3{margin-bottom:16px}.map{height:390px;border-radius:16px;overflow:hidden;background:#0b1724}.map .leaflet-container{background:#091521}
.row{display:flex;justify-content:space-between;align-items:center;gap:10px}.chips{display:flex;gap:7px;flex-wrap:wrap}.chip{padding:7px 10px;border-radius:999px;font-size:11px;background:rgba(255,255,255,.05);color:#b8c7da;border:1px solid var(--line)}.chip.safe{color:var(--green)}.chip.warn{color:var(--yellow)}.chip.danger{color:var(--red)}
.btn{padding:12px 16px;border-radius:12px;color:white;background:linear-gradient(135deg,var(--blue),#765cff);font-weight:700}.btn.secondary{background:rgba(255,255,255,.06);border:1px solid var(--line)}.btn.sos{background:linear-gradient(135deg,#ff3b5c,#b91539);box-shadow:0 12px 35px rgba(255,59,92,.25)}.btn:disabled{opacity:.55;cursor:not-allowed}
.form{display:grid;grid-template-columns:1fr 1fr;gap:14px}.field{display:flex;flex-direction:column;gap:7px}.field.full{grid-column:1/-1}.field label{font-size:12px;color:#9db0c6}.field input,.field select,.field textarea{background:rgba(0,0,0,.2);border:1px solid var(--line);color:white;border-radius:12px;padding:12px 13px;outline:none}.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(57,213,255,.09)}
.table{width:100%;border-collapse:collapse;font-size:12px}.table th,.table td{padding:12px 8px;text-align:left;border-bottom:1px solid var(--line)}.table th{color:#7288a2;font-weight:500}.empty{color:var(--muted);font-size:13px;padding:18px 0}.login{min-height:100vh;display:grid;place-items:center;padding:20px}.loginbox{width:min(100%,480px);padding:30px}.security{display:flex;gap:10px;align-items:center;padding:13px;background:rgba(47,226,160,.07);border:1px solid rgba(47,226,160,.15);border-radius:14px;color:#a9e9d1;font-size:12px;margin:16px 0}.toast{position:fixed;right:20px;bottom:20px;background:#102237;border:1px solid var(--line);padding:14px 17px;border-radius:14px;box-shadow:var(--shadow);z-index:9999}.section{display:none}.section.active{display:block}.qr{width:100px;height:100px;background:white;border-radius:12px;padding:5px}.idcard{background:linear-gradient(135deg,#102d4a,#0b1624);border:1px solid rgba(57,213,255,.22);border-radius:18px;padding:20px}.emergency{display:grid;grid-template-columns:1fr 1fr;gap:10px}.service{padding:13px;border:1px solid var(--line);border-radius:13px;background:rgba(255,255,255,.025)}.service b{font-size:13px}.service p{color:var(--muted);font-size:11px;margin:5px 0 0}.actions{display:flex;gap:9px;flex-wrap:wrap}.note{font-size:11px;color:#70859e;line-height:1.6}
@media(max-width:1000px){.grid{grid-template-columns:1fr}.side{height:auto;position:static}.nav{flex-direction:row;overflow:auto}.nav small{display:none}.stats{grid-template-columns:1fr 1fr}.cards{grid-template-columns:1fr}}
@media(max-width:650px){.container{padding:15px}.top{align-items:flex-start}.hero{padding:20px;display:block}.stats{grid-template-columns:1fr 1fr}.form,.emergency{grid-template-columns:1fr}.field.full{grid-column:auto}.side{padding:10px}.nav button{white-space:nowrap}.map{height:330px}}
</style>
</head>
<body>
<div id="toast" class="toast hidden"></div>
<div id="authView" class="login">
  <div class="loginbox card">
    <div class="brand"><div class="logo">🛡</div><div><b>TRAVELSHIELD</b><span>AI POWERED SMART TOURIST SAFETY</span></div></div>
    <div style="height:22px"></div>
    <h1 id="authTitle" style="font-size:34px">Travel safer. Respond faster.</h1>
    <p class="sub">A unified tourist protection dashboard for trip safety, geofencing, live location, incident response and digital identity.</p>
    <div class="security">✓ Secure authentication &nbsp; • &nbsp; Offline-first client cache &nbsp; • &nbsp; Privacy-aware</div>
    <form id="authForm">
      <div id="nameField" class="field"><label>Full name</label><input id="name" required placeholder="Your full name"></div>
      <div style="height:12px"></div>
      <div class="field"><label>Email</label><input id="email" type="email" required placeholder="you@example.com"></div>
      <div style="height:12px"></div>
      <div class="field"><label>Password</label><input id="password" type="password" minlength="6" required placeholder="Minimum 6 characters"></div>
      <div style="height:16px"></div>
      <button class="btn" id="authBtn" style="width:100%">Create secure profile →</button>
    </form>
    <p style="text-align:center;color:var(--muted);font-size:12px;margin-top:16px"><span id="toggleText">Already registered?</span> <button id="toggleAuth" style="background:none;color:var(--cyan)">Sign in</button></p>
  </div>
</div>

<div id="appView" class="hidden">
<div class="container">
  <div class="top">
    <div class="brand"><div class="logo">🛡</div><div><b>TRAVELSHIELD</b><span>AI POWERED SMART TOURIST SAFETY</span></div></div>
    <div class="actions"><div class="pill"><span class="dot" style="display:inline-block;margin-right:6px"></span> Protection online</div><button class="btn secondary" id="logout">Logout</button></div>
  </div>
  <div class="grid">
    <aside class="side">
      <div class="nav">
        <small>Protection console</small>
        <button class="active" data-tab="dashboard">◈ Overview</button>
        <button data-tab="trip">⌖ Plan safe trip</button>
        <button data-tab="identity">◉ Digital identity</button>
        <button data-tab="incidents">⚠ Incident center</button>
        <button data-tab="services">✚ Nearby assistance</button>
        <button data-tab="admin">▣ Admin overview</button>
      </div>
      <div style="position:absolute;bottom:25px;left:25px;right:25px" class="note">Safety prototype • Geofence and SOS data are stored on the configured backend. For real emergency dispatch, connect approved SMS/GSM/authority APIs.</div>
    </aside>

    <main class="main">
      <section id="dashboard" class="section active">
        <div class="hero card">
          <div>
            <div class="status"><span class="dot"></span> ACTIVE SAFETY MONITORING</div>
            <h1 style="margin-top:12px">Your journey is protected by a live safety layer.</h1>
            <p class="sub">Track your position, evaluate the current risk zone and trigger an incident workflow when help is needed.</p>
            <div class="actions" style="margin-top:20px"><button class="btn sos" id="sosBtn">🚨 EMERGENCY SOS</button><button class="btn secondary" id="locBtn">Use my live location</button></div>
          </div>
          <div class="idcard" style="min-width:220px">
            <div class="note">TOURIST DIGITAL ID</div><h2 id="heroTid" style="margin-top:8px">—</h2><div class="chips" style="margin-top:14px"><span class="chip safe">VERIFIED</span><span class="chip">OFFLINE READY</span></div>
          </div>
        </div>
        <div class="stats">
          <div class="stat card"><p>Current risk</p><div class="num" id="riskNum">SAFE</div><p id="riskZone">Awaiting GPS</p></div>
          <div class="stat card"><p>Trip status</p><div class="num" id="tripNum">—</div><p id="tripSub">No active trip</p></div>
          <div class="stat card"><p>Open incidents</p><div class="num" id="incidentNum">0</div><p>Requires response</p></div>
          <div class="stat card"><p>Location updates</p><div class="num" id="locNum">0</div><p>Recent positions</p></div>
        </div>
        <div class="cards">
          <div class="card"><div class="row"><h3>Live geo-fencing map</h3><span class="chip" id="mapStatus">GPS OFF</span></div><div id="map" class="map"></div><p class="note" style="margin-top:10px">Sample safety zones are used for demonstration. Replace them with authoritative zone data for deployment.</p></div>
          <div class="card"><h3>Risk distribution</h3><canvas id="riskChart" height="230"></canvas><div class="chips" style="margin-top:12px"><span class="chip safe">● Safe</span><span class="chip warn">● Moderate</span><span class="chip danger">● High</span></div></div>
        </div>
      </section>

      <section id="trip" class="section">
        <div class="card"><div class="status"><span class="dot"></span> TRIP PLANNING</div><h2 style="margin-top:8px">Activate a protected journey</h2><p class="sub">Trip details become the safety context for monitoring, emergency contacts and risk analysis.</p>
        <form id="tripForm" class="form" style="margin-top:20px">
          <div class="field full"><label>Destination</label><input name="destination" required placeholder="e.g. Hyderabad, India"></div>
          <div class="field"><label>Start date</label><input type="date" name="startDate" required></div>
          <div class="field"><label>End date</label><input type="date" name="endDate" required></div>
          <div class="field"><label>Nationality</label><input name="nationality" required placeholder="e.g. Indian"></div>
          <div class="field"><label>Passport / ID reference</label><input name="passport" required placeholder="Do not enter sensitive numbers in a demo"></div>
          <div class="field full"><label>Emergency contact</label><input name="emergencyContact" required placeholder="+91 ..."></div>
          <div class="field full"><button class="btn">Activate safety tracking →</button></div>
        </form></div>
        <div class="card" style="margin-top:18px"><h3>Safety workflow</h3><div class="chips"><span class="chip safe">01 Identity verified</span><span class="chip safe">02 Trip registered</span><span class="chip safe">03 GPS monitoring</span><span class="chip warn">04 Risk assessment</span><span class="chip danger">05 SOS response</span></div></div>
      </section>

      <section id="identity" class="section">
        <div class="card"><div class="row"><div><div class="status"><span class="dot"></span> DIGITAL IDENTITY</div><h2 style="margin-top:8px">Verified Tourist Credential</h2></div><button class="btn secondary" onclick="window.print()">Print ID</button></div>
        <div class="idcard" style="margin-top:20px;display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center">
          <div><div class="note">TRAVELSHIELD • SECURE TOURIST ID</div><h1 id="idName" style="font-size:28px;margin-top:9px">—</h1><p class="sub" id="idEmail"></p><div class="chips"><span class="chip safe">✓ VERIFIED</span><span class="chip">CRYPTOGRAPHIC ID</span><span class="chip">OFFLINE CACHE</span></div><p class="note" style="margin-top:14px">ID: <b id="idTid">—</b><br>Use a production blockchain/credential issuer for legally verifiable identity.</p></div>
          <div class="qr" id="qrBox"></div>
        </div></div>
      </section>

      <section id="incidents" class="section">
        <div class="card"><div class="row"><div><div class="status"><span class="dot"></span> INCIDENT RESPONSE</div><h2 style="margin-top:8px">Emergency command center</h2></div><button class="btn sos" id="sosBtn2">SOS NOW</button></div>
        <div class="emergency" style="margin-top:20px"><div class="service"><b>🚨 SOS alert</b><p>Sends your current GPS coordinates to the backend incident log.</p></div><div class="service"><b>📍 Location attached</b><p>Latest available browser GPS position is included when available.</p></div><div class="service"><b>📞 Emergency contact</b><p id="ecText">Not configured</p></div><div class="service"><b>🛰 Offline-first</b><p>Client remains usable during temporary connectivity loss; queued API delivery can be added for field hardware.</p></div></div>
        <h3 style="margin-top:24px">Recent incidents</h3><table class="table"><thead><tr><th>Time</th><th>Type</th><th>Status</th><th>Location</th></tr></thead><tbody id="incidentTable"></tbody></table></div>
      </section>

      <section id="services" class="section">
        <div class="card"><div class="status"><span class="dot"></span> NEARBY ASSISTANCE</div><h2 style="margin-top:8px">Find help around you</h2><p class="sub">Open map searches for police, hospitals, safe places and essential services around your current position.</p>
        <div class="cards" style="margin-top:20px">
          <div class="service"><h3>🚓 Police</h3><p>Search nearby police stations using your live coordinates.</p><button class="btn secondary" onclick="openMaps('police station')">Open map</button></div>
          <div class="service"><h3>🏥 Hospital</h3><p>Find hospitals and emergency medical assistance nearby.</p><button class="btn secondary" onclick="openMaps('hospital')">Open map</button></div>
          <div class="service"><h3>🏨 Safe stay</h3><p>Find hotels/accommodation around the current destination.</p><button class="btn secondary" onclick="openMaps('hotel')">Open map</button></div>
          <div class="service"><h3>📍 Safe zone</h3><p>Search for public places and safe gathering points.</p><button class="btn secondary" onclick="openMaps('safe public place')">Open map</button></div>
        </div></div>
      </section>

      <section id="admin" class="section">
        <div class="card"><div class="status"><span class="dot"></span> ADMIN OVERVIEW</div><h2 style="margin-top:8px">Safety operations snapshot</h2><p class="sub">Demonstration administrator view based on the same backend records. Add real RBAC before production use.</p>
        <div class="stats" style="margin-top:20px"><div class="stat card"><p>Registered tourists</p><div class="num" id="adminUsers">—</div></div><div class="stat card"><p>Open incidents</p><div class="num" id="adminIncidents">—</div></div><div class="stat card"><p>GPS records</p><div class="num" id="adminLocations">—</div></div><div class="stat card"><p>System</p><div class="num" style="font-size:20px">ONLINE</div></div></div>
        <h3>Recent monitored locations</h3><table class="table"><thead><tr><th>User</th><th>Risk</th><th>Coordinates</th><th>Time</th></tr></thead><tbody id="adminTable"></tbody></table></div>
      </section>
    </main>
  </div>
</div>
</div>

<script>
const $=s=>document.querySelector(s);
let token=localStorage.getItem("ts_token"), me=JSON.parse(localStorage.getItem("ts_user")||"null");
let loginMode="register", map, marker, watchId, chart, currentPos=null;

function toast(msg){const t=$("#toast");t.textContent=msg;t.classList.remove("hidden");setTimeout(()=>t.classList.add("hidden"),3500)}
async function api(url,opts={}){opts.headers={...(opts.headers||{}), "Content-Type":"application/json"};if(token)opts.headers.Authorization="Bearer "+token;const r=await fetch(url,opts);let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||"Request failed");return d}
function showApp(){if(!token){$("#authView").classList.remove("hidden");$("#appView").classList.add("hidden");return}$("#authView").classList.add("hidden");$("#appView").classList.remove("hidden");init()}
function setLoginMode(){loginMode=loginMode==="register"?"login":"register";$("#authTitle").textContent=loginMode==="register"?"Travel safer. Respond faster.":"Welcome back to your safety console.";$("#nameField").classList.toggle("hidden",loginMode==="login");$("#name").required=loginMode==="register";$("#authBtn").textContent=loginMode==="register"?"Create secure profile →":"Sign in securely →";$("#toggleText").textContent=loginMode==="register"?"Already registered?":"New to TravelShield?";$("#toggleAuth").textContent=loginMode==="register"?"Sign in":"Create profile"}
$("#toggleAuth").onclick=e=>{e.preventDefault();setLoginMode()}
$("#authForm").onsubmit=async e=>{e.preventDefault();try{const body={email:$("#email").value,password:$("#password").value};if(loginMode==="register")body.fullName=$("#name").value;const d=await api(loginMode==="register"?"/api/auth/register":"/api/auth/login",{method:"POST",body:JSON.stringify(body)});token=d.token;me=d.user;localStorage.setItem("ts_token",token);localStorage.setItem("ts_user",JSON.stringify(me));toast(d.message);showApp()}catch(e){toast(e.message)}}
$("#logout").onclick=()=>{localStorage.removeItem("ts_token");localStorage.removeItem("ts_user");location.reload()}
document.querySelectorAll(".nav button").forEach(b=>b.onclick=()=>{document.querySelectorAll(".nav button").forEach(x=>x.classList.remove("active"));b.classList.add("active");document.querySelectorAll(".section").forEach(x=>x.classList.remove("active"));$("#"+b.dataset.tab).classList.add("active");if(b.dataset.tab==="admin")loadAdmin();if(b.dataset.tab==="incidents")loadIncidents()})

async function init(){
 $("#heroTid").textContent=me?.touristId||"TID-PENDING";$("#idName").textContent=me?.fullName||"Tourist";$("#idEmail").textContent=me?.email||"";$("#idTid").textContent=me?.touristId||"—";$("#ecText").textContent=me?.emergencyContact||"Add an emergency contact in trip planning.";
 $("#qrBox").innerHTML='<div style="color:#111;text-align:center;font:700 10px Inter;padding-top:35px">SCAN<br>'+String(me?.touristId||"TRAVELSHIELD")+'</div>';
 if(!map){map=L.map("map",{zoomControl:false}).setView([17.385,78.4867],12);L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{attribution:"© OpenStreetMap contributors"}).addTo(map);L.circle([17.385,78.4867],{radius:1200,color:"#ff5571",fillOpacity:.08}).addTo(map).bindPopup("Demo high-risk geofence");L.circle([17.4065,78.4772],{radius:2000,color:"#ffc857",fillOpacity:.06}).addTo(map).bindPopup("Demo moderate-risk geofence");}
 try{const trips=await api("/api/trips");if(trips[0]){const t=trips[0];$("#tripNum").textContent="ACTIVE";$("#tripSub").textContent=t.destination;}}catch{}
 await refreshStats();startLocation();
}
async function refreshStats(){try{const inc=await api("/api/incidents"),loc=await api("/api/locations/latest");$("#incidentNum").textContent=inc.filter(x=>x.status==="OPEN").length;$("#locNum").textContent=loc.length;updateChart(loc);if($("#incidents").classList.contains("active"))renderIncidents(inc)}catch{}}
function updateChart(loc){const counts={SAFE:0,MODERATE:0,HIGH:0};loc.forEach(x=>counts[x.riskLevel||"SAFE"]=(counts[x.riskLevel||"SAFE"]||0)+1);if(chart)chart.destroy();chart=new Chart($("#riskChart"),{type:"doughnut",data:{labels:["Safe","Moderate","High"],datasets:[{data:[counts.SAFE||1,counts.MODERATE||0,counts.HIGH||0]}]},options:{plugins:{legend:{display:false}},cutout:"72%"}})}
function startLocation(){if(!navigator.geolocation){toast("GPS is not supported by this browser.");return}watchId=navigator.geolocation.watchPosition(async p=>{currentPos={lat:p.coords.latitude,lng:p.coords.longitude};map.setView([currentPos.lat,currentPos.lng],15);if(!marker)marker=L.marker([currentPos.lat,currentPos.lng]).addTo(map).bindPopup("You are here");else marker.setLatLng([currentPos.lat,currentPos.lng]);$("#mapStatus").textContent="GPS LIVE";try{const r=await api("/api/location",{method:"POST",body:JSON.stringify({latitude:currentPos.lat,longitude:currentPos.lng})});$("#riskNum").textContent=r.level;$("#riskZone").textContent=r.zone;$("#riskNum").style.color=r.level==="HIGH"?"var(--red)":r.level==="MODERATE"?"var(--yellow)":"var(--green)";await refreshStats();}catch{}},()=>{$("#mapStatus").textContent="GPS BLOCKED";toast("Allow location permission to enable live tracking.")},{enableHighAccuracy:true,maximumAge:10000,timeout:15000})}
async function sendSOS(){let p=currentPos;if(!p&&navigator.geolocation){try{p=await new Promise((resolve,reject)=>navigator.geolocation.getCurrentPosition(x=>resolve({lat:x.coords.latitude,lng:x.coords.longitude}),reject,{enableHighAccuracy:true,timeout:8000}))}catch{}}try{const d=await api("/api/incidents",{method:"POST",body:JSON.stringify({type:"SOS",message:"Emergency SOS activated by tourist.",latitude:p?.lat,longitude:p?.lng})});toast("SOS incident created. Emergency workflow activated.");await refreshStats();loadIncidents();}catch(e){toast(e.message)}}
$("#sosBtn").onclick=sendSOS;$("#sosBtn2").onclick=sendSOS;$("#locBtn").onclick=()=>{if(currentPos){map.setView([currentPos.lat,currentPos.lng],16);toast("Centered on your live position.")}else toast("Waiting for GPS permission.")}
$("#tripForm").onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));if(o.endDate<o.startDate){toast("End date cannot be before start date.");return}try{await api("/api/trips",{method:"POST",body:JSON.stringify(o)});toast("Trip registered. Safety monitoring activated.");$("#tripNum").textContent="ACTIVE";$("#tripSub").textContent=o.destination;e.target.reset()}catch(e){toast(e.message)}}
async function loadIncidents(){try{renderIncidents(await api("/api/incidents"))}catch(e){toast(e.message)}}
function renderIncidents(rows){$("#incidentTable").innerHTML=rows.length?rows.map(x=>'<tr><td>'+new Date(x.createdAt).toLocaleString()+'</td><td>'+x.type+'</td><td><span class="chip danger">'+x.status+'</span></td><td>'+(x.latitude?x.latitude.toFixed(4)+", "+x.longitude.toFixed(4):"Unavailable")+'</td></tr>').join(""):'<tr><td colspan="4" class="empty">No incidents recorded.</td></tr>'}
async function loadAdmin(){try{const d=await api("/api/admin/overview");$("#adminUsers").textContent=d.users;$("#adminIncidents").textContent=d.openIncidents;$("#adminLocations").textContent=d.locations.length;$("#adminTable").innerHTML=d.locations.length?d.locations.map(x=>'<tr><td>'+x.userId.slice(0,12)+'…</td><td>'+x.level||x.riskLevel+'</td><td>'+Number(x.latitude).toFixed(4)+", "+Number(x.longitude).toFixed(4)+'</td><td>'+new Date(x.createdAt).toLocaleString()+'</td></tr>').join(""):'<tr><td colspan="4">No location data.</td></tr>'}catch(e){toast(e.message)}}
function openMaps(q) {
  const base = "https://www.google.com/maps/search/" + encodeURIComponent(q);
  const url = currentPos
    ? base + "/@" + currentPos.lat + "," + currentPos.lng + ",14z"
    : base;

  window.open(url, "_blank");
}
if("serviceWorker" in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("/sw.js").catch(()=>{}));
showApp();
</script>
</body>
</html>`;

app.get("/",(req,res)=>res.type("html").send(HTML));
app.get("/{*path}", (req, res, next) => {
  if (req.path.startsWith("/api/") || req.path === "/sw.js") {
    return next();
  }
  res.type("html").send(HTML);
});

connectMongo().finally(()=>app.listen(PORT,()=>console.log(`TravelShield running on http://localhost:${PORT}`)));
