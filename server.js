import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import fs from "fs";
import { openDatabase } from "./database.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// static
app.use("/uploads", express.static(path.join(__dirname, "public", "uploads")));
app.use(express.static(path.join(__dirname, "public")));

const DB = await openDatabase(path.join(__dirname, "uplio.db"));

// JWT config
const JWT_SECRET = process.env.JWT_SECRET || "supersecret123";
const JWT_EXPIRES = "7d";

// ensure upload folders exist
const AVATARS_DIR = path.join(__dirname, "public", "uploads", "avatars");
const HEADERS_DIR = path.join(__dirname, "public", "uploads", "headers");
fs.mkdirSync(AVATARS_DIR, { recursive: true });
fs.mkdirSync(HEADERS_DIR, { recursive: true });

// multer storages
const storageAvatar = multer.diskStorage({
  destination: (req, file, cb) => cb(null, AVATARS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || ".png";
    cb(null, `avatar_${Date.now()}${ext}`);
  }
});
const storageHeader = multer.diskStorage({
  destination: (req, file, cb) => cb(null, HEADERS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || ".jpg";
    cb(null, `header_${Date.now()}${ext}`);
  }
});
const uploadAvatar = multer({ storage: storageAvatar });
const uploadHeader = multer({ storage: storageHeader });

/* ---------------- DB init: create tables if not exists ---------------- */
await DB.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  password TEXT,
  name TEXT,
  picture TEXT,
  provider TEXT,
  createdAt TEXT
);
CREATE TABLE IF NOT EXISTS profiles (
  user_id TEXT PRIMARY KEY,
  name TEXT,
  location TEXT,
  roles TEXT,    -- JSON
  about TEXT,
  offers TEXT,   -- JSON
  needs TEXT,    -- JSON
  projects TEXT, -- JSON
  stats TEXT,    -- JSON
  avatar TEXT,
  header TEXT
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dialog_id TEXT,
  from_user TEXT,
  to_user TEXT,
  text TEXT,
  created_at TEXT
);
`);

/* ---------------- Helpers ---------------- */
function createToken(user) {
  const payload = { id: user.id, email: user.email, provider: user.provider || "local" };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function verifyTokenFromHeader(req) {
  const ah = req.headers.authorization || "";
  if (!ah.startsWith("Bearer ")) return null;
  const token = ah.slice(7);
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

/* ---------------- Auth/Register ---------------- */
// POST /register  { email, password }  OR { credential: "<google id_token>" } (prototype)
app.post("/register", async (req, res) => {
  try {
    const { email, password, credential } = req.body || {};
    if (!email && !credential) return res.status(400).json({ error: "Missing email/password or credential" });

    let user = null;
    if (credential) {
      // NOTE: prototype: decode without verification
      const parts = credential.split(".");
      const payload = parts[1] ? JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) : null;
      if (!payload || !payload.email) return res.status(400).json({ error: "Invalid credential token" });
      const id = payload.sub || `g_${Math.random().toString(36).slice(2,10)}`;
      user = { id, email: payload.email, name: payload.name || "", picture: payload.picture || "", provider: "google", createdAt: new Date().toISOString() };
      // upsert user
      const exists = await DB.get("SELECT * FROM users WHERE email = ?", [user.email]);
      if (exists) {
        await DB.run("UPDATE users SET lastSeen = ? WHERE id = ?", [new Date().toISOString(), exists.id]);
        const token = createToken(exists);
        return res.json({ ok: true, user: { id: exists.id, email: exists.email, name: exists.name, picture: exists.picture, provider: exists.provider }, token });
      } else {
        await DB.run("INSERT INTO users (id,email,name,picture,provider,createdAt) VALUES (?,?,?,?,?,?)",
          [user.id, user.email, user.name, user.picture, user.provider, user.createdAt]);
        const token = createToken(user);
        return res.json({ ok: true, user, token });
      }
    } else {
      // email/password registration (simple)
      if (!/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: "Invalid email" });
      if (!password || password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
      const existing = await DB.get("SELECT * FROM users WHERE email = ?", [email.toLowerCase()]);
      if (existing) {
        // try to login if password matches (for convenience)
        const match = await bcrypt.compare(password, existing.password || "");
        if (!match) return res.status(409).json({ error: "User already exists. Wrong password." });
        const token = createToken(existing);
        return res.json({ ok: true, user: { id: existing.id, email: existing.email, name: existing.name, picture: existing.picture }, token, note: "existing" });
      } else {
        const id = "u_" + Math.random().toString(36).slice(2,10);
        const hashed = await bcrypt.hash(password, 10);
        const createdAt = new Date().toISOString();
        await DB.run("INSERT INTO users (id,email,password,provider,createdAt) VALUES (?,?,?,?,?)", [id, email.toLowerCase(), hashed, "local", createdAt]);
        const userNew = { id, email: email.toLowerCase(), provider: "local", createdAt };
        const token = createToken(userNew);
        return res.json({ ok: true, user: userNew, token });
      }
    }
  } catch (err) {
    console.error("POST /register error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------------- Upload avatar/header ---------------- */
app.post("/upload-avatar", uploadAvatar.single("avatar"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  const rel = `/uploads/avatars/${req.file.filename}`;
  res.json({ ok: true, path: rel });
});
app.post("/upload-header", uploadHeader.single("header"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  const rel = `/uploads/headers/${req.file.filename}`;
  res.json({ ok: true, path: rel });
});

/* ---------------- Profile endpoints ---------------- */
// GET /profile -> returns profile for user from Authorization Bearer token
app.get("/profile", async (req, res) => {
  const payload = verifyTokenFromHeader(req);
  if (!payload) return res.status(401).json({ error: "Unauthorized" });
  try {
    const userId = payload.id;
    // try profile
    const row = await DB.get("SELECT * FROM profiles WHERE user_id = ?", [userId]);
    let profile = null;
    if (row) {
      profile = {
        user_id: row.user_id,
        name: row.name,
        location: row.location,
        roles: row.roles ? JSON.parse(row.roles) : [],
        about: row.about || "",
        offers: row.offers ? JSON.parse(row.offers) : [],
        needs: row.needs ? JSON.parse(row.needs) : [],
        projects: row.projects ? JSON.parse(row.projects) : [],
        stats: row.stats ? JSON.parse(row.stats) : { collaborations: 0, skillsConfirmed: 0, projects: 0 },
        avatar: row.avatar || null,
        header: row.header || null
      };
    } else {
      // fallback: try to get user base info
      const user = await DB.get("SELECT * FROM users WHERE id = ?", [userId]);
      profile = {
        user_id: userId,
        name: user?.name || user?.email || "",
        location: "",
        roles: [],
        about: "",
        offers: [],
        needs: [],
        projects: [],
        stats: { collaborations: 0, skillsConfirmed: 0, projects: 0 },
        avatar: user?.picture || null,
        header: null
      };
    }
    return res.json({ ok: true, profile });
  } catch (e) {
    console.error("GET /profile err", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// POST /profile -> update profile for user (auth)
app.post("/profile", async (req, res) => {
  const payload = verifyTokenFromHeader(req);
  if (!payload) return res.status(401).json({ error: "Unauthorized" });

  const userId = payload.id;
  const {
    name = "",
    location = "",
    roles = [],
    about = "",
    offers = [],
    needs = [],
    projects = [],
    stats = { collaborations: 0, skillsConfirmed: 0, projects: 0 },
    avatar = null,
    header = null
  } = req.body || {};

  try {
    // check if profile exists
    const existing = await DB.get("SELECT * FROM profiles WHERE user_id = ?", [userId]);
    const rolesJSON = JSON.stringify(roles || []);
    const offersJSON = JSON.stringify(offers || []);
    const needsJSON = JSON.stringify(needs || []);
    const projectsJSON = JSON.stringify(projects || []);
    const statsJSON = JSON.stringify(stats || { collaborations: 0, skillsConfirmed: 0, projects: 0 });

    if (existing) {
      // preserve avatar/header if not provided
      const avatarToSave = avatar !== null ? avatar : existing.avatar;
      const headerToSave = header !== null ? header : existing.header;
      await DB.run(`UPDATE profiles SET name=?, location=?, roles=?, about=?, offers=?, needs=?, projects=?, stats=?, avatar=?, header=? WHERE user_id = ?`,
        [name, location, rolesJSON, about, offersJSON, needsJSON, projectsJSON, statsJSON, avatarToSave, headerToSave, userId]);
      const row = await DB.get("SELECT * FROM profiles WHERE user_id = ?", [userId]);
      const profile = {
        user_id: row.user_id,
        name: row.name,
        location: row.location,
        roles: row.roles ? JSON.parse(row.roles) : [],
        about: row.about,
        offers: row.offers ? JSON.parse(row.offers) : [],
        needs: row.needs ? JSON.parse(row.needs) : [],
        projects: row.projects ? JSON.parse(row.projects) : [],
        stats: row.stats ? JSON.parse(row.stats) : {},
        avatar: row.avatar,
        header: row.header
      };
      return res.json({ ok: true, profile });
    } else {
      // insert
      await DB.run(`INSERT INTO profiles (user_id,name,location,roles,about,offers,needs,projects,stats,avatar,header) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        [userId, name, location, rolesJSON, about, offersJSON, needsJSON, projectsJSON, statsJSON, avatar, header]);
      const row = await DB.get("SELECT * FROM profiles WHERE user_id = ?", [userId]);
      const profile = {
        user_id: row.user_id,
        name: row.name,
        location: row.location,
        roles: row.roles ? JSON.parse(row.roles) : [],
        about: row.about,
        offers: row.offers ? JSON.parse(row.offers) : [],
        needs: row.needs ? JSON.parse(row.needs) : [],
        projects: row.projects ? JSON.parse(row.projects) : [],
        stats: row.stats ? JSON.parse(row.stats) : {},
        avatar: row.avatar,
        header: row.header
      };
      return res.json({ ok: true, profile });
    }
  } catch (e) {
    console.error("POST /profile err", e);
    return res.status(500).json({ error: "Server error" });
  }
});

/* ---------------- Misc testing endpoints ---------------- */
app.get("/users", async (req, res) => {
  const rows = await DB.all("SELECT id,email,name,picture,provider,createdAt FROM users");
  res.json(rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`UPLIO running → http://localhost:${PORT}`));
