import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { createClient } from "@supabase/supabase-js";
import ws from "ws"; // <- tambah ini

const app = express();

app.set("trust proxy", 1);

// ── ENV ──
const FR3_KEY        = process.env.FR3_KEY        || "";
const SUPABASE_URL   = process.env.SUPABASE_URL   || "";
const SUPABASE_KEY   = process.env.SUPABASE_ANON_KEY || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://www.fidzzonex.web.id";
const ALLOWED_HOST   = (() => { try { return new URL(ALLOWED_ORIGIN).hostname; } catch(_) { return "fidzzonex.web.id"; } })();

// ── Supabase (server-side only) ──
const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
  realtime: { transport: ws } // <- tambah ini
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "16kb" }));

// ── RATE LIMITERS ──
const apiLimiter   = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });
const topupLimiter = rateLimit({ windowMs: 60_000, max: 5,  standardHeaders: true, legacyHeaders: false });
const authLimiter  = rateLimit({ windowMs: 60_000, max: 10, standardHeaders: true, legacyHeaders: false });

// ── CORS preflight ──
app.options("/api/*", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.status(204).end();
});

// ── GUARD ──
function guard(req, res, next) {
  const ua     = (req.headers["user-agent"] || "").toLowerCase();
  const origin = req.headers["origin"]  || "";
  const ref    = req.headers["referer"] || "";

  // Blokir CLI/bot
  if (["curl","wget","python","httpie","scrapy","go-http","okhttp"].some(b => ua.includes(b))) {
    return res.status(403).json({ status: 403, message: "Forbidden" });
  }

  // Origin ada tapi bukan domain kita → blokir
  if (origin && !origin.includes(ALLOWED_HOST)) {
    return res.status(403).json({ status: 403, message: "Origin tidak diizinkan" });
  }

  // Referer ada tapi bukan domain kita → blokir
  if (!origin && ref && !ref.includes(ALLOWED_HOST)) {
    return res.status(403).json({ status: 403, message: "Referer tidak valid" });
  }

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Cache-Control", "no-store");
  next();
}

// ── Helper: verifikasi JWT dari header Authorization ──
async function getUser(req) {
  const auth  = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const { data, error } = await sb.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
}

// ── Middleware: wajib login ──
async function requireAuth(req, res, next) {
  const user = await getUser(req);
  if (!user) return res.status(401).json({ status: 401, message: "Login diperlukan" });
  req.user = user;
  next();
}

app.use("/api", apiLimiter);

// ── HEALTH CHECK ──
app.get("/api/health", (req, res) => {
  res.json({ status: 200, message: "OK" });
});

// ============================================================
// AUTH
// ============================================================

// Register
app.post("/api/auth/register", guard, authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name)
      return res.status(400).json({ status: 400, message: "Email, password, dan nama wajib diisi" });
    if (password.length < 6)
      return res.status(400).json({ status: 400, message: "Password minimal 6 karakter" });

    const { data, error } = await sb.auth.signUp({
      email, password,
      options: { data: { full_name: name } }
    });

    if (error) {
      let msg = error.message;
      if (msg.includes("already registered")) msg = "Email ini sudah terdaftar.";
      if (msg.includes("Password"))           msg = "Password terlalu lemah.";
      return res.status(400).json({ status: 400, message: msg });
    }

    // Confirm email OFF → session langsung ada
    if (data.session) {
      return res.json({
        status: 200,
        needVerify: false,
        session: {
          access_token:  data.session.access_token,
          refresh_token: data.session.refresh_token,
          expires_at:    data.session.expires_at,
        },
        user: {
          id:    data.user.id,
          email: data.user.email,
          name:  data.user.user_metadata?.full_name || name,
          photo: data.user.user_metadata?.avatar_url || null,
        }
      });
    }

    // Confirm email ON → perlu verifikasi
    return res.json({ status: 200, needVerify: true, email });

  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// Login
app.post("/api/auth/login", guard, authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ status: 400, message: "Email dan password wajib diisi" });

    const { data, error } = await sb.auth.signInWithPassword({ email, password });

    if (error) {
      let msg = error.message;
      if (msg.includes("Invalid login credentials")) msg = "Email atau password salah.";
      if (msg.includes("Email not confirmed"))       msg = "Email belum dikonfirmasi. Cek inbox kamu.";
      if (msg.includes("Too many"))                  msg = "Terlalu banyak percobaan. Tunggu sebentar.";
      return res.status(401).json({ status: 401, message: msg });
    }

    return res.json({
      status: 200,
      session: {
        access_token:  data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at:    data.session.expires_at,
      },
      user: {
        id:    data.user.id,
        email: data.user.email,
        name:  data.user.user_metadata?.full_name || data.user.email.split("@")[0],
        photo: data.user.user_metadata?.avatar_url || null,
      }
    });

  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// Refresh token
app.post("/api/auth/refresh", guard, async (req, res) => {
  try {
    const { refresh_token } = req.body;
    if (!refresh_token)
      return res.status(400).json({ status: 400, message: "refresh_token wajib diisi" });

    const { data, error } = await sb.auth.refreshSession({ refresh_token });
    if (error)
      return res.status(401).json({ status: 401, message: "Session expired. Silakan login ulang." });

    return res.json({
      status: 200,
      session: {
        access_token:  data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at:    data.session.expires_at,
      }
    });
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// Logout
app.post("/api/auth/logout", guard, async (req, res) => {
  // Hapus session dari sisi server
  try {
    const auth  = req.headers["authorization"] || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (token) await sb.auth.admin.signOut(token, "local").catch(() => {});
  } catch (_) {}
  return res.json({ status: 200, message: "Logout berhasil" });
});

// Get current user
app.get("/api/auth/me", guard, async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ status: 401, message: "Belum login" });
    return res.json({
      status: 200,
      user: {
        id:    user.id,
        email: user.email,
        name:  user.user_metadata?.full_name || user.email.split("@")[0],
        photo: user.user_metadata?.avatar_url || null,
      }
    });
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// Google OAuth URL
app.get("/api/auth/google", guard, async (req, res) => {
  try {
    const { data, error } = await sb.auth.signInWithOAuth({
      provider: "google",
      options: { redirectTo: ALLOWED_ORIGIN }
    });
    if (error) return res.status(500).json({ status: 500, message: error.message });
    return res.json({ status: 200, url: data.url });
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// ============================================================
// PAYMENT — semua butuh login
// ============================================================

// Topup / buat QRIS
app.post("/api/topup", guard, requireAuth, topupLimiter, async (req, res) => {
  try {
    const nominal = Number(req.body?.nominal);
    if (!nominal || isNaN(nominal) || nominal < 1000)
      return res.status(400).json({ status: 400, message: "Nominal tidak valid (min Rp 1.000)" });

    // URL & format sesuai dokumentasi fr3newera
    const upstream = await fetch("https://fr3newera.com/api/v1/topup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apikey: FR3_KEY, nominal }),
    });
    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// Cek status transaksi
app.get("/api/check-status", guard, requireAuth, async (req, res) => {
  try {
    const { idTransaksi } = req.query;
    if (!idTransaksi)
      return res.status(400).json({ status: 400, message: "idTransaksi wajib diisi" });

    const upstream = await fetch(
      `https://fr3newera.com/api/v1/check-status?idTransaksi=${encodeURIComponent(idTransaksi)}&apikey=${FR3_KEY}`
    );
    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// Cancel transaksi
app.post("/api/cancel", guard, requireAuth, async (req, res) => {
  try {
    const { idTransaksi } = req.body;
    if (!idTransaksi)
      return res.status(400).json({ status: 400, message: "idTransaksi wajib diisi" });

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

// History transaksi
app.get("/api/history", guard, requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, filter = "all" } = req.query;
    const upstream = await fetch(
      `https://fr3newera.com/api/v1/history?apikey=${FR3_KEY}&page=${page}&limit=${limit}&filter=${filter}`
    );
    const data = await upstream.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ status: 500, message: "Server error: " + err.message });
  }
});

// ── 404 untuk endpoint tidak dikenal ──
app.all("/api/*", (req, res) => {
  res.status(404).json({ status: 404, message: "Endpoint tidak ditemukan" });
});

// ── Serve frontend ──
import { createRequire } from "module";
import { fileURLToPath } from "url";
import path from "path";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.static(path.join(__dirname, "../public")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// ── Start (skip di Vercel) ──
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`✅ Server jalan di http://localhost:${PORT}`));
}

export default app;
