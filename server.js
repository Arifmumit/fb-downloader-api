const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const dns = require("dns").promises;
const net = require("net");
const { Readable } = require("stream");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(express.json({ limit: "16kb" }));

// ১. অনুমোদিত ফ্রন্টএন্ড Origin তালিকা
const allowedOrigins = [
  "https://fbdownprof.blogspot.com"
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

// ২. Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many requests from this IP. Please try again after a few minutes."
  }
});

app.use("/api/", apiLimiter);

// ৩. SSRF সুরক্ষা হেল্পার
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

function decodeEscapedUrl(raw) {
  if (!raw) return null;
  return raw
    .replace(/\\u0025/g, "%")
    .replace(/\\\//g, "/")
    .replace(/&amp;/g, "&");
}

// ৪. Media Extraction ফাংশন (API Key থাকলে API ব্যবহার করবে, নইলে পাবলিক পেজ চেক করবে)
async function extractFacebookMedia(fbUrl, type) {
  if (process.env.RAPIDAPI_KEY && process.env.RAPIDAPI_HOST) {
    try {
      const apiUrl = `https://${process.env.RAPIDAPI_HOST}/download?url=${encodeURIComponent(fbUrl)}`;
      const apiRes = await fetch(apiUrl, {
        method: "GET",
        headers: {
          "x-rapidapi-key": process.env.RAPIDAPI_KEY,
          "x-rapidapi-host": process.env.RAPIDAPI_HOST
        }
      });

      if (apiRes.ok) {
        const json = await apiRes.json();
        const hd = json.hd || (json.links && json.links.hd) || null;
        const sd = json.sd || (json.links && json.links.sd) || null;
        const single = json.url || json.downloadUrl || null;
        if (hd || sd || single) {
          return {
            title: json.title || `Facebook-${type}`,
            hd: hd,
            sd: sd,
            downloadUrl: !hd && !sd ? single : null
          };
        }
      }
    } catch (e) {
      console.error("External API error:", e);
    }
  }

  try {
    const pageRes = await fetch(fbUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9"
      }
    });

    if (pageRes.ok) {
      const html = await pageRes.text();

      const hdMatch =
        html.match(/"playable_url_quality_hd":"(https:[^"]+)"/) ||
        html.match(/"hd_src":"(https:[^"]+)"/);

      const sdMatch =
        html.match(/"playable_url":"(https:[^"]+)"/) ||
        html.match(/"sd_src":"(https:[^"]+)"/);

      const titleMatch = html.match(/<title>(.*?)<\/title>/i);

      const hd = decodeEscapedUrl(hdMatch && hdMatch[1]);
      const sd = decodeEscapedUrl(sdMatch && sdMatch[1]);
      const cleanTitle = titleMatch && titleMatch[1]
        ? titleMatch[1].replace(/\s*\|\s*Facebook.*$/i, "").trim()
        : `Facebook-${type}`;

      if (hd || sd) {
        return {
          title: cleanTitle,
          hd: hd,
          sd: sd,
          downloadUrl: null
        };
      }
    }
  } catch (e) {
    console.error("Page fetch error:", e);
  }

  return {
    title: `Facebook ${type.toUpperCase()} Item`,
    hd: null,
    sd: null,
    downloadUrl: null,
    error: "Could not retrieve direct MP4 stream for this link. Make sure it is a public link or configure a media API key on Render."
  };
}

// ৫. Health Check Route
app.get("/", (req, res) => {
  res.status(200).json({ status: "ok", service: "fb-downloader-backend" });
});

// ৬. Facebook Link Process Endpoint
app.post("/api/fb-download", async (req, res) => {
  try {
    const { url, type } = req.body || {};

    if (!isValidFacebookPageUrl(url)) {
      return res.status(400).json({
        error: "Please provide a valid public Facebook or fb.watch link."
      });
    }

    const cleanType = ["video", "reels", "stories"].includes(type) ? type : "video";
    const result = await extractFacebookMedia(url.trim(), cleanType);

    return res.status(200).json(result);
  } catch (err) {
    console.error("Error in /api/fb-download:", err);
    return res.status(500).json({
      error: "Failed to process the request on the server."
    });
  }
});

// ৭. Direct MP4 Download Stream Endpoint
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

// ৮. Global Error Handler
app.use((err, req, res, next) => {
  if (err && err.message === "CORS_NOT_ALLOWED") {
    return res.status(403).json({ error: "Origin not allowed by CORS." });
  }
  return res.status(500).json({ error: "Internal server error." });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
