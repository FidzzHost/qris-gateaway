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

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, message: "Terlalu banyak request. Tunggu 1 menit." },
});

const topupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { status: 429, message: "Batas topup tercapai. Tunggu sebentar." },
});

app.options("/api/*", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.status(204).end();
});

function strictGuard(req, res, next) {
  const origin = req.headers["origin"] || "";
  const referer = req.headers["referer"] || "";
  const secSite = req.headers["sec-fetch-site"] || "";
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  if (["curl", "wget", "python", "httpie", "postman", "insomnia"].some(b => ua.includes(b))) {
    return res.status(403).json({ status: 403, message: "Forbidden" });
  }

  if (secSite && secSite !== "same-origin" && secSite !== "same-site") {
    return res.status(403).json({ status: 403, message: "Forbidden" });
  }

  const isAllowed = origin.startsWith(ALLOWED_ORIGIN) || referer.startsWith(ALLOWED_ORIGIN);
  if (!isAllowed) {
    return res.status(403).json({ status: 403, message: "Forbidden" });
  }

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");
  res.setHeader("Cache-Control", "no-store");
  next();
}

app.get("/api/config", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Cache-Control", "public, max-age=300");
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    return res.status(500).json({ status: 500, message: "Konfigurasi server belum lengkap." });
  }
  res.json({ supabaseUrl: SUPABASE_URL, supabaseKey: SUPABASE_KEY });
});

app.use("/api", apiLimiter, strictGuard);

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
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

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
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

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
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

app.get("/api/history", async (req, res) => {
  try {
    const { page = 1, limit = 10, filter = "all" } = req.query;
    const upstream = await fetch(
      `https://fr3newera.com/api/v1/history?apikey=${FR3_KEY}&page=${page}&limit=${limit}&filter=${filter}`
    );
    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Proxy error: " + err.message });
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const isVercel = !!process.env.VERCEL;

if (!isVercel) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

export default app;
