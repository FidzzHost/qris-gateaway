import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { createClient } from "@supabase/supabase-js";
import { fileURLToPath } from "url";
import path from "path";

const app = express();
app.set("trust proxy", 1);

// ── ENV ──
const FR3_KEY        = process.env.FR3_KEY || "";
const SUPABASE_URL   = process.env.SUPABASE_URL || "";
const SUPABASE_KEY   = process.env.SUPABASE_ANON_KEY || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://www.fidzzonex.web.id";

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("❌ SUPABASE ENV belum diisi");
}

// ── SUPABASE CLIENT ──
const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

// ── MIDDLEWARE ──
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "16kb" }));

// ── CORS ──
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ── RATE LIMIT ──
const apiLimiter   = rateLimit({ windowMs: 60_000, max: 60 });
const authLimiter  = rateLimit({ windowMs: 60_000, max: 15 });
const topupLimiter = rateLimit({ windowMs: 60_000, max: 5 });

app.use("/api", apiLimiter);

// ── HELPER FORMAT ──
function formatUser(user) {
  return {
    id:    user.id,
    email: user.email,
    name:  user.user_metadata?.full_name || 
           user.user_metadata?.name || 
           user.email?.split("@")[0] || "User",
    photo: user.user_metadata?.avatar_url || user.user_metadata?.picture || null,
  };
}

function formatSession(session) {
  return {
    access_token:  session.access_token,
    refresh_token: session.refresh_token,
    expires_at:    session.expires_at,
  };
}

// ── AUTH HELPER ──
async function getUser(req) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

    if (!token) {
      console.log("❌ No token provided");
      return null;
    }

    const { data, error } = await sb.auth.getUser(token);

    if (error) {
      console.error("Supabase getUser error:", error.message);
      return null;
    }

    return data?.user || null;
  } catch (err) {
    console.error("getUser exception:", err);
    return null;
  }
}

async function requireAuth(req, res, next) {
  const user = await getUser(req);
  if (!user) {
    return res.status(401).json({ 
      status: 401, 
      message: "Unauthorized - Token invalid or expired" 
    });
  }
  req.user = user;
  next();
}

// ── ROUTES ──

// Health
app.get("/api/health", (req, res) => res.json({ status: 200, message: "OK" }));

// ====================== AUTH ======================

// Register
app.post("/api/auth/register", authLimiter, async (req, res) => {
  // ... kode register kamu (biarkan seperti semula)
  // atau kasih tau gw kalau mau gw update juga
});

// Login Email
app.post("/api/auth/login", authLimiter, async (req, res) => {
  // ... kode login email kamu
});

// GOOGLE LOGIN
app.get("/api/auth/google", async (req, res) => {
  try {
    const { data, error } = await sb.auth.signInWithOAuth({
      provider: "google",
      options: {
        redirectTo: ALLOWED_ORIGIN,   // Pastikan ini sama dengan Site URL di Supabase
      }
    });

    if (error) {
      console.error("Google OAuth error:", error);
      return res.status(500).json({ status: 500, message: error.message });
    }

    return res.json({ status: 200, url: data.url });
  } catch (err) {
    console.error("Google route error:", err);
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// CALLBACK (PKCE)
app.post("/api/auth/callback", async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ status: 400, message: "Code wajib diisi" });

    const { data, error } = await sb.auth.exchangeCodeForSession(code);

    if (error) {
      console.error("Exchange code error:", error);
      return res.status(401).json({ status: 401, message: error.message });
    }

    return res.json({
      status: 200,
      session: formatSession(data.session),
      user: formatUser(data.user),
    });
  } catch (err) {
    console.error("Callback error:", err);
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// Refresh Token
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refresh_token } = req.body;
    if (!refresh_token) return res.status(400).json({ status: 400, message: "refresh_token wajib" });

    const { data, error } = await sb.auth.refreshSession({ refresh_token });

    if (error) return res.status(401).json({ status: 401, message: "Refresh gagal" });

    return res.json({
      status: 200,
      session: formatSession(data.session),
      user: formatUser(data.user),
    });
  } catch (err) {
    return res.status(500).json({ status: 500, message: err.message });
  }
});

// Get Current User
app.get("/api/auth/me", requireAuth, (req, res) => {
  return res.json({
    status: 200,
    user: formatUser(req.user),
  });
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  return res.json({ status: 200, message: "Logout berhasil" });
});

// ====================== PAYMENT ======================

app.post("/api/topup", requireAuth, topupLimiter, async (req, res) => {
  // kode topup kamu (tetap)
});

app.get("/api/check-status", requireAuth, async (req, res) => {
  // kode check status kamu
});

app.post("/api/cancel", requireAuth, async (req, res) => {
  // kode cancel kamu
});

app.get("/api/history", requireAuth, async (req, res) => {
  // kode history kamu
});

// 404 API
app.all("/api/*", (req, res) => {
  res.status(404).json({ status: 404, message: "Endpoint tidak ditemukan" });
});

// STATIC FILES + SPA
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname, "../public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

export default app;
