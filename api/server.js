
import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { createClient } from "@supabase/supabase-js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// ── ENV ──
const FR3_KEY        = process.env.FR3_KEY || "";
const SUPABASE_URL   = process.env.SUPABASE_URL || "";
const SUPABASE_KEY   = process.env.SUPABASE_ANON_KEY || "";  // hanya ada di server
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://www.fidzzonex.web.id";
const ALLOWED_HOST   = (() => { try { return new URL(ALLOWED_ORIGIN).hostname; } catch(_) { return "fidzzonex.web.id"; } })();

// ── Supabase client (server-side only, key tidak pernah ke browser) ──
const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "16kb" }));

// ── RATE LIMITERS ──
const apiLimiter   = rateLimit({ windowMs: 60_000, max: 60 });
const topupLimiter = rateLimit({ windowMs: 60_000, max: 5  });
const authLimiter  = rateLimit({ windowMs: 60_000, max: 10 });

// ── CORS preflight ──
app.options("/api/*", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.status(204).end();
});

// ── GUARD: blokir bot & request dari luar domain ──
function guard(req, res, next) {
  const ua     = (req.headers["user-agent"] || "").toLowerCase();
  const origin = req.headers["origin"]  || "";
  const ref    = req.headers["referer"] || "";

  // Blokir CLI/bot
  if (["curl","wget","python","httpie","scrapy","go-http","okhttp"].some(b => ua.includes(b))) {
    return res.status(403).json({ status:403, message:"Forbidden" });
  }
  // Origin ada tapi bukan domain kita → blokir
  if (origin && !origin.includes(ALLOWED_HOST)) {
    return res.status(403).json({ status:403, message:"Origin tidak diizinkan" });
  }
  // Referer ada tapi bukan domain kita → blokir
  if (!origin && ref && !ref.includes(ALLOWED_HOST)) {
    return res.status(403).json({ status:403, message:"Referer tidak valid" });
  }

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Cache-Control", "no-store");
  next();
}

// ── Helper: ambil user dari JWT yang dikirim frontend ──
// Frontend kirim: Authorization: Bearer <access_token>
// Server verifikasi token ke Supabase, tidak perlu expose key
async function getUser(req) {
  const auth  = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const { data, error } = await sb.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
}

app.use("/api", apiLimiter);

// ============================================================
// AUTH ENDPOINTS — semua operasi auth di server, key tidak ke browser
// ============================================================

// Register
app.post("/api/auth/register", guard, authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ status:400, message:"Email, password, dan nama wajib diisi" });
    }
    if (password.length < 6) {
      return res.status(400).json({ status:400, message:"Password minimal 6 karakter" });
    }

    const { data, error } = await sb.auth.signUp({
      email, password,
      options: { data: { full_name: name } }
    });

    if (error) {
      let msg = error.message;
      if (msg.includes("already registered")) msg = "Email ini sudah terdaftar.";
