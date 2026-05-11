import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const FR3_KEY = process.env.FR3_KEY || "";
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://www.fidzzonex.web.id";

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "16kb" }));

const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
const topupLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });
const configLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });

app.options("/api/*", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.status(204).end();
});

// Guard santai buat yang butuh fungsi
function basicGuard(req, res, next) {
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  const referer = req.headers["referer"] || "";
  
  // Cuma blokir curl/wget doang
  if (ua.includes("curl") || ua.includes("wget") || ua.includes("python")) {
    return res.status(403).json({ status: 403, message: "Forbidden" });
  }
  
  // Referer harus dari domain lu
  if (!referer.includes("fidzzonex.web.id")) {
    return res.status(403).json({ status: 403, message: "Bad referer" });
  }
  
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Cache-Control", "no-store");
  next();
}

// /api/config pake guard santai + rate limit doang
app.get("/api/config", configLimiter, basicGuard, (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    return res.status(500).json({ status: 500, message: "Konfigurasi server belum lengkap." });
  }
  res.json({ supabaseUrl: SUPABASE_URL, supabaseKey: SUPABASE_KEY });
});

// Yang lain baru pake limiter biasa
app.use("/api", apiLimiter);

app.post("/api/topup", basicGuard, topupLimiter, async (req, res) => {
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
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

app.get("/api/check-status", basicGuard, async (req, res) => {
  try {
    const { idTransaksi } = req.query;
    if (!idTransaksi) return res.status(400).json({ status: 400, message: "idTransaksi wajib diisi" });
    const upstream = await fetch(`https://fr3newera.com/api/v1/check-status?idTransaksi=${encodeURIComponent(idTransaksi)}&apikey=${FR3_KEY}`);
    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

app.post("/api/cancel", basicGuard, async (req, res) => {
  try {
    const { idTransaksi } = req.body;
    if (!idTransaksi) return res.status(400).json({ status: 400, message: "idTransaksi wajib diisi" });
    const upstream = await fetch("https://fr3newera.com/api/v1/topup/cancel", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apikey: FR3_KEY, idTransaksi }),
    });
    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

app.all("/api/*", (req, res) => {
  res.status(404).json({ status: 404, message: "Not Found" });
});

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

const isVercel = !!process.env.VERCEL;
if (!isVercel) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
}
export default app;
