import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { createClient } from "@supabase/supabase-js";
import ws from "ws"; // ← tambah

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// ENV
const FR3_KEY        = process.env.FR3_KEY || "";
const SUPABASE_URL   = process.env.SUPABASE_URL || "";
const SUPABASE_KEY   = process.env.SUPABASE_ANON_KEY || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://www.fidzzonex.web.id";
const ALLOWED_HOST   = (() => { 
  try { return new URL(ALLOWED_ORIGIN).hostname; } 
  catch(_) { return "fidzzonex.web.id"; } 
})();

// Supabase client - tambah realtime.transport
const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
  realtime: { transport: ws } // ← ini fix nya
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "16kb" }));

// ── RATE LIMITERS ──
const apiLimiter   = rateLimit({ windowMs: 60000, max: 60 });
const topupLimiter = rateLimit({ windowMs: 60000, max: 5  });
const authLimiter  = rateLimit({ windowMs: 60000, max: 10 });

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

  if (["curl","wget","python","httpie","scrapy","go-http","okhttp"].some(b => ua.includes(b))) {
    return res.status(403).json({ status:403, message:"Forbidden" });
  }
  if (origin && !origin.includes(ALLOWED_HOST)) {
    return res.status(403).json({ status:403, message:"Origin tidak diizinkan" });
  }
  if (!origin && ref && !ref.includes(ALLOWED_HOST)) {
    return res.status(403).json({ status:403, message:"Referer tidak valid" });
  }

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Cache-Control", "no-store");
  next();
}

// ── Helper: ambil user dari JWT ──
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
// AUTH ENDPOINTS
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
      email, 
      password,
      options: { data: { full_name: name } }
    });

    if (error) {
      let msg = error.message;
      if (msg.includes("already registered")) msg = "Email ini sudah terdaftar.";
      return res.status(400).json({ status:400, message: msg });
    }

    res.json({ status:200, message:"Registrasi berhasil. Cek email untuk verifikasi." });
  } catch (e) {
    res.status(500).json({ status:500, message:"Server error" });
  }
});

// Login
app.post("/api/auth/login", guard, authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ status:400, message:"Email dan password wajib diisi" });
    }

    const { data, error } = await sb.auth.signInWithPassword({ email, password });
    if (error) {
      return res.status(401).json({ status:401, message:"Email atau password salah" });
    }

    res.json({ 
      status:200, 
      session: data.session,
      user: data.user 
    });
  } catch (e) {
    res.status(500).json({ status:500, message:"Server error" });
  }
});

// Logout
app.post("/api/auth/logout", guard, async (req, res) => {
  try {
    const auth = req.headers["authorization"] || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (token) {
      await sb.auth.signOut();
    }
    res.json({ status:200, message:"Logout berhasil" });
  } catch (e) {
    res.status(500).json({ status:500, message:"Server error" });
  }
});

// Get current user
app.get("/api/auth/me", guard, async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ status:401, message:"Belum login" });
    res.json({ status:200, user });
  } catch (e) {
    res.status(500).json({ status:500, message:"Server error" });
  }
});

// ============================================================
// TOPUP ENDPOINTS
// ============================================================

// Create topup
app.post("/api/topup", guard, topupLimiter, async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ status:401, message:"Login diperlukan" });

    const { nominal } = req.body;
    if (!nominal || nominal < 10000) {
      return res.status(400).json({ status:400, message:"Minimal topup Rp10.000" });
    }

    // Panggil API FR3 lu di sini
    const fr3Res = await fetch("https://api.fr3.id/v1/topup", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${FR3_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ 
        user_id: user.id,
        nominal 
      })
    });

    const fr3Data = await fr3Res.json();
    res.json(fr3Data);
  } catch (e) {
    res.status(500).json({ status:500, message:"Server error" });
  }
});

// Check status
app.get("/api/check-status", guard, async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ status:401, message:"Login diperlukan" });

    const { idTransaksi } = req.query;
    if (!idTransaksi) {
      return res.status(400).json({ status:400, message:"idTransaksi wajib diisi" });
    }

    const fr3Res = await fetch(`https://api.fr3.id/v1/status?id=${idTransaksi}`, {
      headers: { "Authorization": `Bearer ${FR3_KEY}` }
    });

    const fr3Data = await fr3Res.json();
    res.json(fr3Data);
  } catch (e) {
    res.status(500).json({ status:500, message:"Server error" });
  }
});

// Cancel transaction
app.post("/api/cancel", guard, async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ status:401, message:"Login diperlukan" });

    const { idTransaksi } = req.body;
    if (!idTransaksi) {
      return res.status(400).json({ status:400, message:"idTransaksi wajib diisi" });
    }

    const fr3Res = await fetch("https://api.fr3.id/v1/cancel", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${FR3_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ idTransaksi })
    });

    const fr3Data = await fr3Res.json();
    res.json(fr3Data);
  } catch (e) {
    res.status(500).json({ status:500, message:"Server error" });
  }
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status:200, message:"OK" });
});

// Export untuk Vercel
export default app;
