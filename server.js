import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// ============================================================
// ENVIRONMENT
// ============================================================
const FR3_KEY        = process.env.FR3_KEY        || "";
const SUPABASE_URL   = process.env.SUPABASE_URL   || "";
const SUPABASE_KEY   = process.env.SUPABASE_ANON_KEY || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://www.fidzz-codex.my.id";
const PORT           = process.env.PORT || 3000;

if (!FR3_KEY || !SUPABASE_URL || !SUPABASE_KEY) {
  console.error("❌  Missing required env vars. Check .env file.");
  process.exit(1);
}

// ============================================================
// SECURITY HEADERS (helmet)
// ============================================================
app.use(
  helmet({
    contentSecurityPolicy: false, // diatur manual di bawah
  })
);

// ============================================================
// BODY PARSER
// ============================================================
app.use(express.json({ limit: "16kb" }));

// ============================================================
// SERVE STATIC FILES (index.html, aset, dll)
// ============================================================
app.use(
  express.static(__dirname, {
    index: "index.html",
    etag: true,
    maxAge: "1h",
  })
);

// ============================================================
// RATE LIMITER — per IP
// ============================================================
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 menit
  max: 30,               // maks 30 request/menit per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, message: "Terlalu banyak request. Coba lagi 1 menit." },
});

const topupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,                // maks 5 topup/menit per IP (lebih ketat)
  message: { status: 429, message: "Batas topup tercapai. Tunggu sebentar." },
});

// ============================================================
// MIDDLEWARE KEAMANAN API
// — Blokir curl / non-browser / akses dari origin lain
// ============================================================
function guardAPI(req, res, next) {
  // 1. Cek Origin — harus dari domain sendiri (browser kirim ini otomatis)
  const origin  = req.headers["origin"]  || "";
  const referer = req.headers["referer"] || "";

  const originOk  = origin.startsWith(ALLOWED_ORIGIN);
  const refererOk = referer.startsWith(ALLOWED_ORIGIN);

  // Kalau ada Origin header tapi bukan domain kita → tolak
  if (origin && !originOk) {
    return res.status(403).json({ status: 403, message: "Forbidden: origin tidak diizinkan." });
  }

  // 2. Cek X-Requested-With — wajib dikirim dari fetch() di index.html
  if (req.headers["x-requested-with"] !== "XMLHttpRequest") {
    return res.status(403).json({ status: 403, message: "Forbidden: akses langsung tidak diizinkan." });
  }

  // 3. Blokir User-Agent curl/wget/python-requests/dll
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  const blockedUA = ["curl", "wget", "python-requests", "httpie", "insomnia", "postman"];
  if (blockedUA.some(b => ua.includes(b))) {
    return res.status(403).json({ status: 403, message: "Forbidden." });
  }

  // 4. Tambah CORS header — hanya izinkan ALLOWED_ORIGIN
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
  res.setHeader("Cache-Control", "no-store");

  next();
}

// Handle preflight OPTIONS untuk semua route /api/*
app.options("/api/*", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
  res.status(204).end();
});

// Terapkan guard + rate limiter ke semua /api/*
app.use("/api", apiLimiter, guardAPI);

// ============================================================
// ROUTE: GET /api/config
// Kirim Supabase URL + key ke frontend (aman: hanya dari browser kita)
// ============================================================
app.get("/api/config", (req, res) => {
  res.json({
    supabaseUrl: SUPABASE_URL,
    supabaseKey: SUPABASE_KEY,
  });
});

// ============================================================
// ROUTE: POST /api/topup
// ============================================================
app.post("/api/topup", topupLimiter, async (req, res) => {
  try {
    const { nominal } = req.body;
    if (!nominal || isNaN(nominal) || Number(nominal) < 1000) {
      return res.status(400).json({ status: 400, message: "Nominal tidak valid (min Rp 1.000)" });
    }

    const upstream = await fetch("https://fr3newera.com/api/v1/topup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apikey: FR3_KEY, nominal: Number(nominal) }),
    });

    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    console.error("[topup]", err.message);
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// ============================================================
// ROUTE: GET /api/check-status
// ============================================================
app.get("/api/check-status", async (req, res) => {
  try {
    const { idTransaksi } = req.query;
    if (!idTransaksi) {
      return res.status(400).json({ status: 400, message: "idTransaksi wajib diisi" });
    }

    const upstream = await fetch(
      `https://fr3newera.com/api/v1/check-status?idTransaksi=${encodeURIComponent(idTransaksi)}&apikey=${FR3_KEY}`
    );

    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    console.error("[check-status]", err.message);
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// ============================================================
// ROUTE: POST /api/cancel
// ============================================================
app.post("/api/cancel", async (req, res) => {
  try {
    const { idTransaksi } = req.body;
    if (!idTransaksi) {
      return res.status(400).json({ status: 400, message: "idTransaksi wajib diisi" });
    }

    const upstream = await fetch("https://fr3newera.com/api/v1/topup/cancel", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apikey: FR3_KEY, idTransaksi }),
    });

    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    console.error("[cancel]", err.message);
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// ============================================================
// ROUTE: GET /api/history
// ============================================================
app.get("/api/history", async (req, res) => {
  try {
    const { page = 1, limit = 10, filter = "all" } = req.query;
    const url = `https://fr3newera.com/api/v1/history?apikey=${FR3_KEY}&page=${page}&limit=${limit}&filter=${filter}`;
    const upstream = await fetch(url);
    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    console.error("[history]", err.message);
    return res.status(500).json({ status: 500, message: "Proxy error: " + err.message });
  }
});

// ============================================================
// FALLBACK — semua route lain → index.html (SPA)
// ============================================================
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log(`✅  Server running at http://localhost:${PORT}`);
});
