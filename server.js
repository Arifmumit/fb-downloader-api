const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const dns = require("dns").promises;
const net = require("net");
const { Readable } = require("stream");

const app = express();
const PORT = process.env.PORT || 3000;

// Render-এর পেছনে সঠিক client IP পাওয়ার জন্য
app.set("trust proxy", 1);

app.use(express.json({ limit: "16kb" }));

// ১. আপনার Blogger ওয়েবসাইটের অনুমোদিত ডোমেইন তালিকা
const allowedOrigins = [
  "https://fbdownprof.blogspot.com"
  // ভবিষ্যতে কাস্টম ডোমেইন যুক্ত করলে নিচে কমা দিয়ে যুক্ত করবেন:
  // "https://www.yourdomain.com"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS_NOT_ALLOWED"));
      }
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"]
  })
);

app.options("*", cors());

// ২. Rate Limiting (অতিরিক্ত বা স্প্যাম রিকোয়েস্ট ঠেকানোর জন্য)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // ১৫ মিনিট
  max: 60, // প্রতি IP থেকে সর্বোচ্চ ৬০ রিকোয়েস্ট
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many requests from this IP. Please try again after a few minutes."
  }
});

app.use("/api/", apiLimiter);

// ৩. SSRF সুরক্ষা হেল্পার (প্রাইভেট/লোকাল/মেটাডাটা IP ব্লক করার জন্য)
function isPrivateOrReservedIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
    return false;
  }
  if (version === 6) {
    const normalized = ip.toLowerCase();
    if (normalized === "::" || normalized === "::1") return true;
    if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
    if (normalized.startsWith("fe80:")) return true;
    if (normalized.startsWith("::ffff:")) {
      return isPrivateOrReservedIp(normalized.replace("::ffff:", ""));
    }
    return false;
  }
  return true;
}

async function validateSafeMediaUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string" || rawUrl.length > 2048) {
    return { ok: false, reason: "Invalid media URL." };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { ok: false, reason: "Malformed media URL." };
  }

  if (parsed.protocol !== "https:") {
    return { ok: false, reason: "Only HTTPS media URLs are allowed." };
  }

  if (parsed.username || parsed.password) {
    return { ok: false, reason: "Credentials in URL are not allowed." };
  }

  const host = parsed.hostname.toLowerCase();
  const isAllowedHost =
    host === "fbcdn.net" ||
    host.endsWith(".fbcdn.net") ||
    host === "facebook.com" ||
    host.endsWith(".facebook.com");

  if (!isAllowedHost) {
    return { ok: false, reason: "Media host is not on the allowlist." };
  }

  if (net.isIP(host)) {
    if (isPrivateOrReservedIp(host)) {
      return { ok: false, reason: "Private or reserved IP is blocked." };
    }
    return { ok: true, url: parsed.toString() };
  }

  try {
    const records = await dns.lookup(host, { all: true });
    if (!records.length) {
      return { ok: false, reason: "Could not resolve media hostname." };
    }
    for (const rec of records) {
      if (isPrivateOrReservedIp(rec.address)) {
        return { ok: false, reason: "Hostname resolves to a restricted IP." };
      }
    }
  } catch {
    return { ok: false, reason: "DNS lookup failed." };
  }

  return { ok: true, url: parsed.toString() };
}

function sanitizeFilename(name) {
  const cleaned = String(name || "facebook-video")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80);
  const base = cleaned || "facebook-video";
  return base.toLowerCase().endsWith(".mp4") ? base : `${base}.mp4`;
}

function isValidFacebookPageUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string" || rawUrl.length > 1024) {
    return false;
  }
  try {
    const parsed = new URL(rawUrl.trim());
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    const host = parsed.hostname.toLowerCase();
    return (
      host === "facebook.com" ||
      host.endsWith(".facebook.com") ||
      host === "fb.watch" ||
      host.endsWith(".fb.watch")
    );
  } catch {
    return false;
  }
}

// ৪. সার্ভার চালু আছে কি না যাচাই করার Health Check রাউট
app.get("/", (req, res) => {
  res.status(200).json({ status: "ok", service: "fb-downloader-backend" });
});

// ৫. Facebook Link যাচাই ও রেসপন্স রাউট
app.post("/api/fb-download", async (req, res) => {
  try {
    const { url, type } = req.body || {};

    if (!isValidFacebookPageUrl(url)) {
      return res.status(400).json({
        error: "Please provide a valid public Facebook or fb.watch link."
      });
    }

    const cleanType = ["video", "reels", "stories"].includes(type) ? type : "video";

    return res.status(200).json({
      title: `Facebook ${cleanType.toUpperCase()} Item`,
      hd: null,
      sd: null,
      downloadUrl: null,
      message: "Backend connected with https://fbdownprof.blogspot.com. Connect your public media extraction logic to return valid MP4 URLs."
    });
  } catch (err) {
    console.error("Error in /api/fb-download:", err);
    return res.status(500).json({
      error: "Failed to process the request on the server."
    });
  }
});

// ৬. সরাসরি MP4 ফাইল ডাউনলোড করানোর রাউট (নতুন ট্যাবে প্লে না হয়ে attachment হিসেবে ডাউনলোড হবে)
app.get("/api/stream-download", async (req, res) => {
  const { url, title } = req.query || {};
  const check = await validateSafeMediaUrl(url);

  if (!check.ok) {
    return res.status(400).json({ error: check.reason });
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const upstreamRes = await fetch(check.url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0"
      }
    });

    if ([301, 302, 303, 307, 308].includes(upstreamRes.status)) {
      const location = upstreamRes.headers.get("location");
      const redirectCheck = await validateSafeMediaUrl(location);
      if (!redirectCheck.ok) {
        return res.status(400).json({ error: "Redirect target is not allowed." });
      }
      return res.redirect(
        302,
        `/api/stream-download?url=${encodeURIComponent(redirectCheck.url)}&title=${encodeURIComponent(title || "facebook-video.mp4")}`
      );
    }

    if (!upstreamRes.ok || !upstreamRes.body) {
      return res.status(502).json({ error: "Could not fetch media stream from upstream." });
    }

    const safeName = sanitizeFilename(title);
    const contentLength = upstreamRes.headers.get("content-length");

    res.setHeader("Content-Type", "video/mp4");
    res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (contentLength) {
      res.setHeader("Content-Length", contentLength);
    }

    Readable.fromWeb(upstreamRes.body).pipe(res);
  } catch (err) {
    console.error("Stream download error:", err);
    if (!res.headersSent) {
      const status = err && err.name === "AbortError" ? 504 : 500;
      res.status(status).json({ error: "Failed to stream MP4 file." });
    }
  } finally {
    clearTimeout(timeoutId);
  }
});

// ৭. Global Error Handler
app.use((err, req, res, next) => {
  if (err && err.message === "CORS_NOT_ALLOWED") {
    return res.status(403).json({ error: "Origin not allowed by CORS." });
  }
  return res.status(500).json({ error: "Internal server error." });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
