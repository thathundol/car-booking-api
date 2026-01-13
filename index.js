const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

const app = express();

// ====== CONFIG ======
const APP_JWT_SECRET = process.env.APP_JWT_SECRET || "change-me";
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log("API running on http://localhost:" + PORT));


// LINE Channel ID (ถ้าใส่ไว้จะเช็ค aud ให้)
const LINE_CHANNEL_ID = process.env.LINE_CHANNEL_ID || "";

// อนุญาต CORS เฉพาะโดเมนที่ต้องใช้ (ใส่ของคุณได้หลายอันคั่นด้วย ,)
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ====== MIDDLEWARE ======
app.use(express.json());

// CORS: ถ้าไม่ตั้ง ALLOWED_ORIGINS จะ allow ทั้งหมดเพื่อ dev ให้เดินก่อน
app.use(
  cors({
    origin: function (origin, callback) {
      // origin จะเป็น undefined ได้ในกรณีเรียกจาก curl/postman
      if (!origin) return callback(null, true);

      if (ALLOWED_ORIGINS.length === 0) return callback(null, true);

      if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);

      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// รองรับ preflight
app.options("*", cors());

// ====== DB ======
const db = new sqlite3.Database("./db.sqlite");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      line_user_id TEXT UNIQUE,
      display_name TEXT,
      picture_url TEXT,
      updated_at TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS cars (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      plate TEXT,
      seats INTEGER,
      image_url TEXT,
      active INTEGER DEFAULT 1
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      car_id INTEGER,
      start_at TEXT,
      end_at TEXT,
      purpose TEXT,
      status TEXT,
      created_at TEXT
    )
  `);

  // seed รถตัวอย่าง (ครั้งเดียว)
  db.get("SELECT COUNT(*) as c FROM cars", (err, row) => {
    if (!err && row.c === 0) {
      const stmt = db.prepare(
        "INSERT INTO cars (name, plate, seats, image_url) VALUES (?,?,?,?)"
      );
      stmt.run("Toyota Vios", "กข-1234", 4, "https://picsum.photos/seed/vios/600/400");
      stmt.run("Isuzu D-Max", "ขค-5678", 2, "https://picsum.photos/seed/dmax/600/400");
      stmt.finalize();
    }
  });
});

// ====== Helpers ======
function nowISO() {
  return new Date().toISOString();
}

// MVP: decode อย่างเดียวให้ระบบเดินก่อน
function decodeIdTokenUnsafe(idToken) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Invalid idToken");

  // บาง token เป็น base64url ต้องแทน - _ ก่อน decode
  const payloadB64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const payload = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8"));
  return payload; // { sub, name, picture, aud, iss, exp, ... }
}

function signAppToken(lineUserId) {
  return jwt.sign({ lineUserId }, APP_JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });

  try {
    const decoded = jwt.verify(token, APP_JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}

// ====== Routes ======
app.get("/", (req, res) => res.send("OK"));

// 1) Auth with LINE idToken
app.post("/auth/line", (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: "idToken required" });

    const payload = decodeIdTokenUnsafe(idToken);

    // debug log ช่วยมากเวลาไล่ปัญหา
    console.log("[/auth/line] payload.sub:", payload.sub);
    console.log("[/auth/line] payload.aud:", payload.aud);

    // basic checks (ขั้นต่ำ)
    if (!payload.sub) return res.status(400).json({ error: "token missing sub" });

    if (LINE_CHANNEL_ID && payload.aud !== LINE_CHANNEL_ID) {
      return res.status(401).json({ error: "aud mismatch" });
    }

    const lineUserId = payload.sub;
    const displayName = payload.name || "";
    const pictureUrl = payload.picture || "";

    db.run(
      `INSERT INTO users (line_user_id, display_name, picture_url, updated_at)
       VALUES (?,?,?,?)
       ON CONFLICT(line_user_id) DO UPDATE SET
         display_name=excluded.display_name,
         picture_url=excluded.picture_url,
         updated_at=excluded.updated_at
      `,
      [lineUserId, displayName, pictureUrl, nowISO()],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });

        const appToken = signAppToken(lineUserId);
        return res.json({
          appToken,
          user: { lineUserId, displayName, pictureUrl },
        });
      }
    );
  } catch (e) {
    console.error("POST /auth/line error:", e);
    return res.status(400).json({ error: e.message || "bad request" });
  }
});

// 2) Available cars
app.get("/cars/available", auth, (req, res) => {
  const { startAt, endAt } = req.query;
  if (!startAt || !endAt) return res.status(400).json({ error: "startAt & endAt required" });

  const sql = `
    SELECT c.*
    FROM cars c
    WHERE c.active=1
    AND c.id NOT IN (
      SELECT b.car_id
      FROM bookings b
      WHERE b.status IN ('PENDING_APPROVAL','APPROVED')
      AND NOT (b.end_at <= ? OR b.start_at >= ?)
    )
    ORDER BY c.id DESC
  `;

  db.all(sql, [startAt, endAt], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ cars: rows });
  });
});

// 3) Create booking
app.post("/bookings", auth, (req, res) => {
  const { carId, startAt, endAt, purpose } = req.body;
  if (!carId || !startAt || !endAt) {
    return res.status(400).json({ error: "carId,startAt,endAt required" });
  }

  db.get("SELECT id FROM users WHERE line_user_id = ?", [req.user.lineUserId], (err, userRow) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!userRow) return res.status(401).json({ error: "user not found, re-login" });

    db.run(
      `INSERT INTO bookings (user_id, car_id, start_at, end_at, purpose, status, created_at)
       VALUES (?,?,?,?,?,'PENDING_APPROVAL',?)`,
      [userRow.id, carId, startAt, endAt, purpose || "", nowISO()],
      function (err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        return res.json({ bookingId: this.lastID, status: "PENDING_APPROVAL" });
      }
    );
  });
});

app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
