import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { createClient } from "@supabase/supabase-js";
import { fileURLToPath } from "url";
import path from "path";

const app = express();
app.set("trust proxy", 1);

// ── ENV ──
const FR3_KEY        = process.env.FR3_KEY            || "";
const SUPABASE_URL   = process.env.SUPABASE_URL        || "";
const SUPABASE_KEY   = process.env.SUPABASE_ANON_KEY   || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN      || "https://fidzzonex.web.id";

if (!SUPABASE_URL || !SUPABASE_KEY) console.error("❌ SUPABASE ENV belum diisi");

// ── SUPABASE ──
const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

// ── MIDDLEWARE ──
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "16kb" }));

// ── CORS ──
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin",      ALLOWED_ORIGIN);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers",     "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods",     "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ── RATE LIMIT ──
const apiLimiter   = rateLimit({ windowMs: 60_000, max: 60,  standardHeaders: true, legacyHeaders: false });
const authLimiter  = rateLimit({ windowMs: 60_000, max: 10,  standardHeaders: true, legacyHeaders: false });
const topupLimiter = rateLimit({ windowMs: 60_000, max: 5,   standardHeaders: true, legacyHeaders: false });

app.use("/api", apiLimiter);

// ── HELPER: format user object yang konsisten untuk frontend ──
function formatUser(user) {
  return {
    id:    user.id,
    email: user.email,
    name:  user.user_metadata?.full_name || user.user_metadata?.name || user.email?.split("@")[0] || "User",
    photo: user.user_metadata?.avatar_url || user.user_metadata?.picture || null,
  };
}

// ── HELPER: format session ──
function formatSession(session) {
  return {
    access_token:  session.access_token,
    refresh_token: session.refresh_token,
    expires_at:    session.expires_at,
  };
}

// ── HELPER AUTH ──
async function getUser(req) {
  try {
    const auth  = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return null;
    const { data, error } = await sb.auth.getUser(token);
    if (error || !data?.user) return null;
    return data.user;
  } catch { return null; }
}

async function requireAuth(req, res, next) {
  const user = await getUser(req);
  if (!user) return res.status(401).json({ status: 401, message: "Login diperlukan" });
  req.user = user;
  next();
}

// ── HEALTH ──
app.get("/api/health", (req, res) => res.json({ status: 200, message: "OK" }));

// ======================================================
// AUTH
// ======================================================

// REGISTER
app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name)
      return res.status(400).json({ status: 400, message: "Semua field wajib diisi" });
    if (password.length < 6)
      return res.status(400).json({ status: 400, message: "Password minimal 6 karakter" });

    const { data, error } = await sb.auth.signUp({
      email, password,
      options: { data: { full_name: name } }
    });

    if (error) {
      let msg = error.message;
      if (msg.includes("already registered")) msg = "Email ini sudah terdaftar.";
      return res.status(400).json({ status: 400, message: msg });
    }

    // Confirm email OFF → session langsung ada
    if (data.session) {
      return res.json({
        status:     200,
        needVerify: false,
        session:    formatSession(data.session),
        user:       formatUser(data.user),
      });
    }

    // Confirm email ON → perlu verifikasi email dulu
    return res.json({ status: 200, needVerify: true, email });

  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// LOGIN
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ status: 400, message: "Email dan password wajib diisi" });

    const { data, error } = await sb.auth.signInWithPassword({ email, password });

    if (error) {
      let msg = "Email atau password salah.";
      if (error.message.includes("Email not confirmed")) msg = "Email belum dikonfirmasi. Cek inbox kamu.";
      if (error.message.includes("Too many"))           msg = "Terlalu banyak percobaan. Tunggu sebentar.";
      return res.status(401).json({ status: 401, message: msg });
    }

    return res.json({
      status:  200,
      session: formatSession(data.session),
      user:    formatUser(data.user),
    });

  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// GOOGLE LOGIN — generate URL, frontend redirect kesana
app.get("/api/auth/google", async (req, res) => {
  try {
    const { data, error } = await sb.auth.signInWithOAuth({
      provider: "google",
      options: {
        redirectTo: "https://www.fidzzonex.web.id/",   // ← HARUS EXACT (dengan www atau tanpa, sesuaikan)
        // JANGAN tambah query params lain kalau tidak perlu
      }
    });

    if (error) return res.status(500).json({ status: 500, message: error.message });
    
    return res.json({ status: 200, url: data.url });
  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// CALLBACK — exchange PKCE code → session (dipanggil frontend setelah redirect)
app.post("/api/auth/callback", async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ status: 400, message: "code wajib diisi" });

    const { data, error } = await sb.auth.exchangeCodeForSession(code);
    if (error) return res.status(401).json({ status: 401, message: error.message });

    return res.json({
      status:  200,
      session: formatSession(data.session),
      user:    formatUser(data.user),
    });
  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// REFRESH TOKEN
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refresh_token } = req.body;
    if (!refresh_token)
      return res.status(400).json({ status: 400, message: "refresh_token wajib diisi" });

    const { data, error } = await sb.auth.refreshSession({ refresh_token });
    if (error) return res.status(401).json({ status: 401, message: "Session expired. Silakan login ulang." });

    return res.json({
      status:  200,
      session: formatSession(data.session),
      user:    formatUser(data.user),
    });
  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// GET CURRENT USER — verifikasi token
app.get("/api/auth/me", requireAuth, (req, res) => {
  return res.json({
    status: 200,
    user:   formatUser(req.user),
  });
});

// LOGOUT
app.post("/api/auth/logout", (req, res) => {
  return res.json({ status: 200, message: "Logout berhasil" });
});

// ======================================================
// PAYMENT — semua butuh login
// ======================================================

app.post("/api/topup", requireAuth, topupLimiter, async (req, res) => {
  try {
    const nominal = Number(req.body.nominal);
    if (!nominal || nominal < 1000)
      return res.status(400).json({ status: 400, message: "Nominal minimal Rp 1.000" });

    const upstream = await fetch("https://fr3newera.com/api/v1/topup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apikey: FR3_KEY, nominal }),
    });
    return res.json(await upstream.json());
  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

app.get("/api/check-status", requireAuth, async (req, res) => {
  try {
    const { idTransaksi } = req.query;
    if (!idTransaksi)
      return res.status(400).json({ status: 400, message: "idTransaksi wajib diisi" });

    const upstream = await fetch(
      `https://fr3newera.com/api/v1/check-status?idTransaksi=${encodeURIComponent(idTransaksi)}&apikey=${FR3_KEY}`
    );
    return res.json(await upstream.json());
  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

app.post("/api/cancel", requireAuth, async (req, res) => {
  try {
    const { idTransaksi } = req.body;
    if (!idTransaksi)
      return res.status(400).json({ status: 400, message: "idTransaksi wajib diisi" });

    const upstream = await fetch("https://fr3newera.com/api/v1/topup/cancel", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apikey: FR3_KEY, idTransaksi }),
    });
    return res.json(await upstream.json());
  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

app.get("/api/history", requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, filter = "all" } = req.query;
    const upstream = await fetch(
      `https://fr3newera.com/api/v1/history?apikey=${FR3_KEY}&page=${page}&limit=${limit}&filter=${filter}`
    );
    return res.json(await upstream.json());
  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// ── 404 API ──
app.all("/api/*", (req, res) => {
  return res.status(404).json({ status: 404, message: "Endpoint tidak ditemukan" });
});

// ── STATIC ──
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname, "../public")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// ── START LOCAL ──
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`✅ Server jalan di http://localhost:${PORT}`));
}

export default app;
