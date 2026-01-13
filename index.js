const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const BOOTSTRAP_SUPERADMIN_LINE_ID =
  process.env.BOOTSTRAP_SUPERADMIN_LINE_ID || "";


const app = express();

// ====== CONFIG ======
const APP_JWT_SECRET = process.env.APP_JWT_SECRET || "change-me";
const PORT = Number(process.env.PORT) || 10000; // Render ใช้ env PORT

const LINE_CHANNEL_ID = process.env.LINE_CHANNEL_ID || "";

// Render แนะนำเขียนลง /tmp ถ้าไม่มี persistent disk
const DB_PATH = process.env.DATABASE_PATH || "/tmp/db.sqlite";

// อนุญาต CORS เฉพาะโดเมนที่ต้องใช้ (คั่นด้วย ,)
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ====== MIDDLEWARE ======
app.use(express.json());

// CORS
app.use(
  cors({
    origin: function (origin, callback) {
      // curl/postman ไม่มี origin
      if (!origin) return callback(null, true);

      // dev: ถ้าไม่กำหนด allowlist ให้ผ่านหมด
      if (ALLOWED_ORIGINS.length === 0) return callback(null, true);

      if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);

      // ถ้าไม่อยู่ใน allowlist ให้ตอบ error
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// preflight
app.options("*", cors());

// ====== DB ======
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error("❌ DB open error:", err.message);
  else console.log("✅ DB opened:", DB_PATH);
});

db.serialize(() => {
  db.run("PRAGMA journal_mode = WAL;");
  db.run("PRAGMA foreign_keys = ON;");

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      line_user_id TEXT UNIQUE,
      display_name TEXT,
      picture_url TEXT,

      -- register fields
      first_name TEXT,
      last_name TEXT,
      department TEXT,
      role TEXT DEFAULT 'USER',
      profile_completed INTEGER DEFAULT 0,

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
      admin_id INTEGER,
      admin_note TEXT,
      created_at TEXT,

      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(car_id) REFERENCES cars(id),
      FOREIGN KEY(admin_id) REFERENCES users(id)
    )
  `);

  // Seed รถตัวอย่าง (ครั้งเดียว)
  db.get("SELECT COUNT(*) as c FROM cars", (err, row) => {
    if (!err && row && row.c === 0) {
      const stmt = db.prepare(
        "INSERT INTO cars (name, plate, seats, image_url) VALUES (?,?,?,?)"
      );
      stmt.run("Toyota Vios", "กข-1234", 4, "https://picsum.photos/seed/vios/600/400");
      stmt.run("Isuzu D-Max", "ขค-5678", 2, "https://picsum.photos/seed/dmax/600/400");
      stmt.finalize();
      console.log("✅ Seed cars inserted");
    }
  });
});

// ====== Helpers ======

function bootstrapSuperAdmin(lineUserId) {
  if (!BOOTSTRAP_SUPERADMIN_LINE_ID) return;
  if (lineUserId !== BOOTSTRAP_SUPERADMIN_LINE_ID) return;

  db.run(
    `
    UPDATE users
    SET role='SUPERADMIN', updated_at=?
    WHERE line_user_id=? AND role!='SUPERADMIN'
    `,
    [nowISO(), lineUserId],
    (err) => {
      if (err) {
        console.error("❌ bootstrap SUPERADMIN error:", err.message);
      } else {
        console.log("👑 SUPERADMIN ensured for", lineUserId);
      }
    }
  );
}

function nowISO() {
  return new Date().toISOString();
}

// base64url decode ให้ถูก + padding
function base64UrlDecode(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  return Buffer.from(s, "base64").toString("utf8");
}

// MVP: decode อย่างเดียว (ยังไม่ verify signature)
function decodeIdTokenUnsafe(idToken) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Invalid idToken");
  const payloadJson = base64UrlDecode(parts[1]);
  return JSON.parse(payloadJson);
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
    req.user = decoded; // { lineUserId }
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}

function requireAdmin(req, res, next) {
  db.get(
    "SELECT role FROM users WHERE line_user_id = ?",
    [req.user.lineUserId],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(401).json({ error: "user not found" });
      if (row.role !== "ADMIN" && row.role !== "SUPERADMIN") {
        return res.status(403).json({ error: "admin only" });
      }
      next();
    }
  );
}

function requireSuperAdmin(req, res, next) {
  db.get(
    "SELECT role FROM users WHERE line_user_id = ?",
    [req.user.lineUserId],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(401).json({ error: "user not found" });
      if (row.role !== "SUPERADMIN") {
        return res.status(403).json({ error: "superadmin only" });
      }
      next();
    }
  );
}

// หลัง insert/update user สำเร็จ
bootstrapSuperAdmin(lineUserId);



// ====== Routes ======
app.get("/", (req, res) => res.send("OK"));
app.get("/health", (req, res) => res.json({ ok: true, time: nowISO() }));

// 1) Auth with LINE idToken
app.post("/auth/line", (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: "idToken required" });

    const payload = decodeIdTokenUnsafe(idToken);

    console.log("[/auth/line] sub:", payload.sub, "aud:", payload.aud);

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

        db.get(
          `SELECT line_user_id, display_name, picture_url, first_name, last_name, department, role, profile_completed
           FROM users WHERE line_user_id = ?`,
          [lineUserId],
          (err2, userRow) => {
            if (err2) return res.status(500).json({ error: err2.message });

            const appToken = signAppToken(lineUserId);
            return res.json({
              appToken,
              user: userRow,
            });
          }
        );
      }
    );
  } catch (e) {
    console.error("POST /auth/line error:", e);
    return res.status(400).json({ error: e.message || "bad request" });
  }
});

// 2) Get my profile
app.get("/me", auth, (req, res) => {
  db.get(
    `SELECT line_user_id, display_name, picture_url, first_name, last_name, department, role, profile_completed
     FROM users WHERE line_user_id = ?`,
    [req.user.lineUserId],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: "user not found" });
      return res.json({ user: row });
    }
  );
});

// 3) Register / update profile
app.post("/me/profile", auth, (req, res) => {
  const { first_name, last_name, department } = req.body;

  if (!first_name || !last_name || !department) {
    return res.status(400).json({ error: "first_name, last_name, department required" });
  }

  db.run(
    `UPDATE users
     SET first_name=?, last_name=?, department=?, profile_completed=1, updated_at=?
     WHERE line_user_id=?`,
    [first_name, last_name, department, nowISO(), req.user.lineUserId],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ ok: true });
    }
  );
});

// 4) Available cars (ตามช่วงเวลา)
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

// 5) Create booking (มี check overlap + require profile)
app.post("/bookings", auth, (req, res) => {
  const { carId, startAt, endAt, purpose } = req.body;
  if (!carId || !startAt || !endAt) {
    return res.status(400).json({ error: "carId,startAt,endAt required" });
  }

  db.get(
    `SELECT id, profile_completed FROM users WHERE line_user_id = ?`,
    [req.user.lineUserId],
    (err, userRow) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!userRow) return res.status(401).json({ error: "user not found, re-login" });

      if (!userRow.profile_completed) {
        return res.status(403).json({ error: "profile not completed" });
      }

      // กันจองซ้อน
      db.get(
        `SELECT id FROM bookings
         WHERE car_id=?
         AND status IN ('PENDING_APPROVAL','APPROVED')
         AND NOT (end_at <= ? OR start_at >= ?)
         LIMIT 1`,
        [carId, startAt, endAt],
        (err2, conflict) => {
          if (err2) return res.status(500).json({ error: err2.message });
          if (conflict) return res.status(409).json({ error: "time conflict" });

          db.run(
            `INSERT INTO bookings (user_id, car_id, start_at, end_at, purpose, status, created_at)
             VALUES (?,?,?,?,?,'PENDING_APPROVAL',?)`,
            [userRow.id, carId, startAt, endAt, purpose || "", nowISO()],
            function (err3) {
              if (err3) return res.status(500).json({ error: err3.message });
              return res.json({ bookingId: this.lastID, status: "PENDING_APPROVAL" });
            }
          );
        }
      );
    }
  );
});



// ====== Admin Dashboard APIs ======

// 6) List pending bookings
app.get("/admin/bookings", auth, requireAdmin, (req, res) => {
  const status = req.query.status || "PENDING_APPROVAL";

  const sql = `
    SELECT
      b.id, b.start_at, b.end_at, b.purpose, b.status, b.created_at,
      u.first_name, u.last_name, u.department, u.display_name,
      c.name as car_name, c.plate as car_plate
    FROM bookings b
    JOIN users u ON u.id = b.user_id
    JOIN cars c ON c.id = b.car_id
    WHERE b.status = ?
    ORDER BY b.created_at DESC
    LIMIT 200
  `;

  db.all(sql, [status], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ bookings: rows });
  });
});

// 7) Approve
app.post("/admin/bookings/:id/approve", auth, requireAdmin, (req, res) => {
  const bookingId = Number(req.params.id);
  const { admin_note } = req.body;

  // หา admin id
  db.get(
    "SELECT id FROM users WHERE line_user_id = ?",
    [req.user.lineUserId],
    (err, adminRow) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!adminRow) return res.status(401).json({ error: "admin user not found" });

      // update สถานะ + ใส่ admin
      db.run(
        `UPDATE bookings
         SET status='APPROVED', admin_id=?, admin_note=?
         WHERE id=? AND status='PENDING_APPROVAL'`,
        [adminRow.id, admin_note || "", bookingId],
        function (err2) {
          if (err2) return res.status(500).json({ error: err2.message });
          if (this.changes === 0) return res.status(404).json({ error: "not found or not pending" });
          return res.json({ ok: true });
        }
      );
    }
  );
});

// 8) Reject
app.post("/admin/bookings/:id/reject", auth, requireAdmin, (req, res) => {
  const bookingId = Number(req.params.id);
  const { admin_note } = req.body;

  db.get(
    "SELECT id FROM users WHERE line_user_id = ?",
    [req.user.lineUserId],
    (err, adminRow) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!adminRow) return res.status(401).json({ error: "admin user not found" });

      db.run(
        `UPDATE bookings
         SET status='REJECTED', admin_id=?, admin_note=?
         WHERE id=? AND status='PENDING_APPROVAL'`,
        [adminRow.id, admin_note || "", bookingId],
        function (err2) {
          if (err2) return res.status(500).json({ error: err2.message });
          if (this.changes === 0) return res.status(404).json({ error: "not found or not pending" });
          return res.json({ ok: true });
        }
      );
    }
  );
});

// ====== Super Admin: User management ======

// list users (สำหรับตั้ง role)
app.get("/admin/users", auth, requireSuperAdmin, (req, res) => {
  const q = (req.query.q || "").trim();

  const baseSql = `
    SELECT id, line_user_id, display_name, first_name, last_name, department, role, profile_completed, updated_at
    FROM users
  `;

  const sql = q
    ? baseSql + ` WHERE display_name LIKE ? OR first_name LIKE ? OR last_name LIKE ? OR department LIKE ? ORDER BY updated_at DESC LIMIT 200`
    : baseSql + ` ORDER BY updated_at DESC LIMIT 200`;

  const params = q ? Array(4).fill(`%${q}%`) : [];

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ users: rows });
  });
});

// set role ให้ user คนอื่น
app.post("/admin/users/:id/role", auth, requireSuperAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const role = (req.body.role || "").toUpperCase();

  const allowed = new Set(["USER", "ADMIN", "SUPERADMIN"]);
  if (!allowed.has(role)) return res.status(400).json({ error: "invalid role" });

  db.run(
    `UPDATE users SET role=?, updated_at=? WHERE id=?`,
    [role, nowISO(), userId],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: "user not found" });
      return res.json({ ok: true, role });
    }
  );
});


// ✅ listen แค่ครั้งเดียว
app.listen(PORT, () => {
  console.log(`✅ API running on port ${PORT}`);
});
