import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { createClient } from "@supabase/supabase-js";
import ws from "ws";
import { fileURLToPath } from "url";
import path from "path";

const app = express();

app.set("trust proxy", 1);

// ── ENV ──
const FR3_KEY = process.env.FR3_KEY || "";
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://fidzzonex.web.id";
// ── VALIDASI ENV ──
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("SUPABASE ENV BELUM DIISI");
}

// ── SUPABASE ──
const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
  realtime: {
    transport: ws,
  },
});

// ── MIDDLEWARE ──
app.use(helmet({ contentSecurityPolicy: false }));

app.use(
  express.json({
    limit: "16kb",
  })
);

// ── CORS ──
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

// ── RATE LIMIT ──
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const topupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api", apiLimiter);

// ── HELPER AUTH ──
async function getUser(req) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ")
      ? auth.slice(7)
      : null;

    if (!token) return null;

    const { data, error } = await sb.auth.getUser(token);

    if (error || !data?.user) return null;

    return data.user;
  } catch {
    return null;
  }
}

async function requireAuth(req, res, next) {
  const user = await getUser(req);

  if (!user) {
    return res.status(401).json({
      status: 401,
      message: "Login diperlukan",
    });
  }

  req.user = user;
  next();
}

// ── HEALTH ──
app.get("/api/health", (req, res) => {
  res.json({
    status: 200,
    message: "OK",
  });
});

// ======================================================
// AUTH
// ======================================================

// REGISTER
app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({
        status: 400,
        message: "Semua field wajib diisi",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        status: 400,
        message: "Password minimal 6 karakter",
      });
    }

    const { data, error } = await sb.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: name,
        },
      },
    });

    if (error) {
      return res.status(400).json({
        status: 400,
        message: error.message,
      });
    }

    return res.json({
      status: 200,
      user: data.user,
      session: data.session,
    });
  } catch (err) {
    return res.status(500).json({
      status: 500,
      message: err.message,
    });
  }
});

// LOGIN
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data, error } =
      await sb.auth.signInWithPassword({
        email,
        password,
      });

    if (error) {
      return res.status(401).json({
        status: 401,
        message: "Email atau password salah",
      });
    }

    return res.json({
      status: 200,
      user: data.user,
      session: data.session,
    });
  } catch (err) {
    return res.status(500).json({
      status: 500,
      message: err.message,
    });
  }
});

// GOOGLE LOGIN
app.get("/api/auth/google", async (req, res) => {
  try {
    const { data, error } =
      await sb.auth.signInWithOAuth({
        provider: "google",
        options: {
          redirectTo: `${ALLOWED_ORIGIN}`,
        },
      });

    if (error) {
      return res.status(500).json({
        status: 500,
        message: error.message,
      });
    }

    return res.json({
      status: 200,
      url: data.url,
    });
  } catch (err) {
    return res.status(500).json({
      status: 500,
      message: err.message,
    });
  }
});

// REFRESH
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({
        status: 400,
        message: "refresh_token wajib diisi",
      });
    }

    const { data, error } =
      await sb.auth.refreshSession({
        refresh_token,
      });

    if (error) {
      return res.status(401).json({
        status: 401,
        message: "Session expired",
      });
    }

    return res.json({
      status: 200,
      session: data.session,
    });
  } catch (err) {
    return res.status(500).json({
      status: 500,
      message: err.message,
    });
  }
});

// ME
app.get("/api/auth/me", requireAuth, async (req, res) => {
  return res.json({
    status: 200,
    user: req.user,
  });
});

// LOGOUT
app.post("/api/auth/logout", async (req, res) => {
  return res.json({
    status: 200,
    message: "Logout berhasil",
  });
});

// ======================================================
// PAYMENT
// ======================================================

// TOPUP
app.post(
  "/api/topup",
  requireAuth,
  topupLimiter,
  async (req, res) => {
    try {
      const nominal = Number(req.body.nominal);

      if (!nominal || nominal < 1000) {
        return res.status(400).json({
          status: 400,
          message: "Nominal minimal Rp1000",
        });
      }

      const upstream = await fetch(
        "https://fr3newera.com/api/v1/topup",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            apikey: FR3_KEY,
            nominal,
          }),
        }
      );

      const data = await upstream.json();

      return res.json(data);
    } catch (err) {
      return res.status(500).json({
        status: 500,
        message: err.message,
      });
    }
  }
);

// CHECK STATUS
app.get(
  "/api/check-status",
  requireAuth,
  async (req, res) => {
    try {
      const { idTransaksi } = req.query;

      const upstream = await fetch(
        `https://fr3newera.com/api/v1/check-status?idTransaksi=${encodeURIComponent(
          idTransaksi
        )}&apikey=${FR3_KEY}`
      );

      const data = await upstream.json();

      return res.json(data);
    } catch (err) {
      return res.status(500).json({
        status: 500,
        message: err.message,
      });
    }
  }
);

// CANCEL
app.post(
  "/api/cancel",
  requireAuth,
  async (req, res) => {
    try {
      const { idTransaksi } = req.body;

      const upstream = await fetch(
        "https://fr3newera.com/api/v1/topup/cancel",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            apikey: FR3_KEY,
            idTransaksi,
          }),
        }
      );

      const data = await upstream.json();

      return res.json(data);
    } catch (err) {
      return res.status(500).json({
        status: 500,
        message: err.message,
      });
    }
  }
);

// HISTORY
app.get(
  "/api/history",
  requireAuth,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 10,
        filter = "all",
      } = req.query;

      const upstream = await fetch(
        `https://fr3newera.com/api/v1/history?apikey=${FR3_KEY}&page=${page}&limit=${limit}&filter=${filter}`
      );

      const data = await upstream.json();

      return res.json(data);
    } catch (err) {
      return res.status(500).json({
        status: 500,
        message: err.message,
      });
    }
  }
);

// ── 404 API ──
app.all("/api/*", (req, res) => {
  return res.status(404).json({
    status: 404,
    message: "Endpoint tidak ditemukan",
  });
});

// ── STATIC FILE ──
const __dirname = path.dirname(
  fileURLToPath(import.meta.url)
);

app.use(
  express.static(
    path.join(__dirname, "../public")
  )
);

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../public/index.html")
  );
});

// ── START LOCAL ──
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;

  app.listen(PORT, () => {
    console.log(
      `Server jalan di http://localhost:${PORT}`
    );
  });
}

export default app;
