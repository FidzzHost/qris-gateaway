import express from "express"
import rateLimit from "express-rate-limit"
import helmet from "helmet"
import { createClient } from "@supabase/supabase-js"
import ws from "ws"
import { fileURLToPath } from "url"
import path from "path"
import { AbortController } from "abort-controller"

const app = express()

app.disable("x-powered-by")
app.set("trust proxy", 1)

const FR3_KEY = process.env.FR3_KEY || ""
const SUPABASE_URL = process.env.SUPABASE_URL || ""
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || ""
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://www.fidzzonex.web.id"

if (!SUPABASE_URL) {
  throw new Error("SUPABASE_URL belum diisi")
}

if (!SUPABASE_KEY) {
  throw new Error("SUPABASE_ANON_KEY belum diisi")
}

if (!FR3_KEY) {
  throw new Error("FR3_KEY belum diisi")
}

const ALLOWED_HOST = (() => {
  try {
    return new URL(ALLOWED_ORIGIN).hostname
  } catch {
    return "fidzzonex.web.id"
  }
})()

const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  },
  realtime: {
    transport: ws
  }
})

app.use(
  helmet({
    contentSecurityPolicy: false
  })
)

app.use(express.json({ limit: "16kb" }))

const apiLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
})

const topupLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
})

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
})

app.options("/api/*", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
  res.setHeader("Access-Control-Allow-Credentials", "true")
  res.status(204).end()
})

function getHostname(value) {
  try {
    return new URL(value).hostname
  } catch {
    return ""
  }
}

function guard(req, res, next) {
  const ua = (req.headers["user-agent"] || "").toLowerCase()
  const origin = req.headers["origin"] || ""
  const referer = req.headers["referer"] || ""

  const blocked = [
    "curl",
    "wget",
    "python",
    "httpie",
    "scrapy",
    "go-http",
    "okhttp"
  ]

  if (blocked.some(v => ua.includes(v))) {
    return res.status(403).json({
      status: 403,
      message: "Forbidden"
    })
  }

  const originHost = getHostname(origin)
  const refererHost = getHostname(referer)

  if (origin && originHost !== ALLOWED_HOST) {
    return res.status(403).json({
      status: 403,
      message: "Origin tidak diizinkan"
    })
  }

  if (!origin && referer && refererHost !== ALLOWED_HOST) {
    return res.status(403).json({
      status: 403,
      message: "Referer tidak valid"
    })
  }

  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
  res.setHeader("Access-Control-Allow-Credentials", "true")
  res.setHeader("Cache-Control", "no-store")

  next()
}

async function getUser(req) {
  const auth = req.headers.authorization || ""
  const token = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : null

  if (!token) return null

  const { data, error } = await sb.auth.getUser(token)

  if (error || !data?.user) return null

  return data.user
}

async function requireAuth(req, res, next) {
  const user = await getUser(req)

  if (!user) {
    return res.status(401).json({
      status: 401,
      message: "Login diperlukan"
    })
  }

  req.user = user
  next()
}

async function safeFetch(url, options = {}) {
  const controller = new AbortController()

  const timeout = setTimeout(() => {
    controller.abort()
  }, 15000)

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    })

    return response
  } finally {
    clearTimeout(timeout)
  }
}

app.use("/api", apiLimiter)

app.get("/api/health", (_, res) => {
  res.json({
    status: 200,
    uptime: process.uptime(),
    timestamp: Date.now()
  })
})

app.post("/api/auth/login", guard, authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({
        status: 400,
        message: "Email dan password wajib diisi"
      })
    }

    const { data, error } = await sb.auth.signInWithPassword({
      email,
      password
    })

    if (error) {
      let msg = error.message

      if (msg.includes("Invalid login credentials")) {
        msg = "Email atau password salah."
      }

      if (msg.includes("Email not confirmed")) {
        msg = "Email belum dikonfirmasi."
      }

      return res.status(401).json({
        status: 401,
        message: msg
      })
    }

    return res.json({
      status: 200,
      session: {
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at: data.session.expires_at
      },
      user: {
        id: data.user.id,
        email: data.user.email,
        name:
          data.user.user_metadata?.full_name ||
          data.user.email.split("@")[0]
      }
    })
  } catch (err) {
    return res.status(500).json({
      status: 500,
      message: err.message
    })
  }
})

app.post(
  "/api/topup",
  guard,
  requireAuth,
  topupLimiter,
  async (req, res) => {
    try {
      const nominal = Number(req.body?.nominal)

      if (!nominal || nominal < 1000) {
        return res.status(400).json({
          status: 400,
          message: "Nominal tidak valid"
        })
      }

      const upstream = await safeFetch(
        "https://fr3newera.com/api/v1/topup",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            apikey: FR3_KEY,
            nominal
          })
        }
      )

      const data = await upstream.json()

      return res.status(200).json(data)
    } catch (err) {
      return res.status(500).json({
        status: 500,
        message: err.message
      })
    }
  }
)

app.all("/api/*", (_, res) => {
  res.status(404).json({
    status: 404,
    message: "Endpoint tidak ditemukan"
  })
})

const __dirname = path.dirname(fileURLToPath(import.meta.url))

app.use(express.static(path.join(__dirname, "../public")))

app.get("*", (_, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"))
})

if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000

  app.listen(PORT, () => {
    console.log(`Server running on ${PORT}`)
  })
}

export default app
