/**
 * Phase 8 — div-ai-light
 * Fast triage: popup events + screenshot meta/images
 * Uses xAI Grok API when XAI_API_KEY / GROK_API_KEY set; else heuristic triage
 */
import express from "express";
import cors from "cors";
import { createHmac, randomBytes } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { rateLimit, securityHeaders, applySecurity, pathFirewall } from "./hardening.js";
import { putJsonFile, deleteFile, githubDbEnabled } from "./githubDb.js";


async function persistTriage(record) {
  if (!githubDbEnabled()) return;
  const id = record.id || record.triageId;
  try {
    await putJsonFile(`ai/triage/${id}.json`, record, `triage ${id}`);
  } catch (e) {
    console.error("triage gh", e.message);
  }
}

async function requestScanCleanup(scanId, token) {
  if (!scanId) return;
  const deep = (process.env.DEEP_A_URL || "https://div-scan-deep-a.onrender.com").replace(/\/$/, "");
  try {
    await fetch(`${deep}/v1/scan/${scanId}/cleanup`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token || ""}`, "Content-Type": "application/json" },
      body: "{}",
    });
    if (githubDbEnabled()) {
      await deleteFile(`ai/triage/${scanId}.json`, `cleanup triage ${scanId}`).catch(() => {});
    }
  } catch (e) {
    console.error("cleanup request", e.message);
  }
}

const app = express();
app.set("trust proxy", 1);
applySecurity(app);
app.use(cors({ origin: true }));
app.use(express.json({ limit: "8mb" }));

const PORT = process.env.PORT || 3000;
const SERVICE = "div-ai-light";
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-div-auth";
const AUTH_URL = (process.env.AUTH_URL || "https://div-auth.onrender.com").replace(/\/$/, "");
const SERVICE_SECRET = process.env.SERVICE_SECRET || JWT_SECRET;
const SERVICE_NAME = process.env.SERVICE_NAME || "div-ai-light";
const RAW_LLM_KEY = process.env.GROQ_API_KEY || process.env.XAI_API_KEY || process.env.GROK_API_KEY || "";
const IS_GROQ = RAW_LLM_KEY.startsWith("gsk_");
const XAI_API_KEY = RAW_LLM_KEY; // used as generic LLM key
const XAI_BASE = (process.env.XAI_BASE_URL || (IS_GROQ ? "https://api.groq.com/openai/v1" : "https://api.x.ai/v1")).replace(/\/$/, "");
const XAI_MODEL = process.env.XAI_MODEL || process.env.GROQ_MODEL || (IS_GROQ ? "llama-3.3-70b-versatile" : "grok-2-latest");
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || "";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.0-flash";
const EXPLORIUM_API_KEY = process.env.EXPLORIUM_API_KEY || "";
const EXPLORIUM_BASE = (process.env.EXPLORIUM_BASE_URL || "https://api.explorium.ai").replace(/\/$/, "");
const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });
const JOBS = join(DATA, "triage.json");

function load(file, fb) {
  if (!existsSync(file)) return fb;
  try { return JSON.parse(readFileSync(file, "utf8")); } catch { return fb; }
}
function save(file, data) { writeFileSync(file, JSON.stringify(data, null, 2)); }

function ok(res, data, status = 200) {
  return res.status(status).json({ ok: true, data, version: "v1", service: SERVICE });
}
function fail(res, status, code, message) {
  return res.status(status).json({ ok: false, error: { code, message }, service: SERVICE });
}

function verifyJwt(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const expect = createHmac("sha256", JWT_SECRET).update(`${h}.${b}`).digest("base64url");
  if (s !== expect) return null;
  try {
    const payload = JSON.parse(Buffer.from(b, "base64url").toString("utf8"));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  let payload = verifyJwt(token);
  if (payload) { req.user = payload; return next(); }
  // Fallback: ask auth service (handles free-tier JWT secret lag)
  fetch((process.env.AUTH_URL || "https://div-auth.onrender.com").replace(/\/$/, "") + "/v1/auth/me", {
    headers: { Authorization: "Bearer " + token },
  }).then(async (r) => {
    if (!r.ok) return fail(res, 401, "unauthorized", "valid token required");
    const j = await r.json();
    const u = j?.data?.user;
    if (!u) return fail(res, 401, "unauthorized", "valid token required");
    req.user = { sub: u.id, role: u.role, email: u.email };
    next();
  }).catch(() => fail(res, 401, "unauthorized", "valid token required"));
}

const RISK_WORDS = [
  "aimbot", "esp", "hack", "mod menu", "injector", "floating", "bypass",
  "panel", "auto headshot", "wallhack", "radar", "cheat",
];

function heuristicTriage({ events = [], screenshots = [] }) {
  const hits = [];
  let score = 0;
  for (const e of events) {
    const blob = `${e.title || ""} ${e.text || ""} ${e.packageName || ""}`.toLowerCase();
    for (const w of RISK_WORDS) {
      if (blob.includes(w)) {
        hits.push({ source: "event", keyword: w, packageName: e.packageName });
        score += 12;
      }
    }
    if (Array.isArray(e.riskKeywordHits)) {
      for (const w of e.riskKeywordHits) {
        hits.push({ source: "event_flag", keyword: w, packageName: e.packageName });
        score += 10;
      }
    }
  }
  for (const s of screenshots) {
    const note = String(s.note || "").toLowerCase();
    for (const w of RISK_WORDS) {
      if (note.includes(w)) {
        hits.push({ source: "screenshot_note", keyword: w });
        score += 8;
      }
    }
  }
  score = Math.min(100, score);
  const verdict = score >= 70 ? "likely_cheat_ui" : score >= 35 ? "suspicious" : "clean_or_unclear";
  return {
    engine: "heuristic",
    score,
    verdict,
    hits,
    summary:
      verdict === "clean_or_unclear"
        ? "No strong cheat-panel keywords in provided popup text/meta."
        : `Keyword risk signals detected (${hits.length}). Review recommended.`,
  };
}


async function geminiTriage({ events = [], screenshots = [] }) {
  if (!GEMINI_API_KEY) return null;
  const textParts = events.slice(0, 25).map((e, i) =>
    `Event${i + 1}: pkg=${e.packageName || "?"} title=${e.title || ""} text=${e.text || ""}`
  ).join("\n");
  const prompt =
    "You are a mobile integrity triage assistant. Decide if popup/notification text suggests cheating panels, injectors, ESP/aimbot for mobile games. " +
    "Reply JSON only: {\"score\":0-100,\"verdict\":\"clean_or_unclear|suspicious|likely_cheat_ui\",\"summary\":\"...\",\"indicators\":[\"...\"]}\n\n" +
    textParts;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2 },
    }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j?.error?.message || "gemini error");
  const raw = j?.candidates?.[0]?.content?.parts?.[0]?.text || "";
  let parsed;
  try {
    const m = raw.match(/\{[\s\S]*\}/);
    parsed = JSON.parse(m ? m[0] : raw);
  } catch {
    parsed = { score: 0, verdict: "clean_or_unclear", summary: raw.slice(0, 400), indicators: [] };
  }
  return {
    engine: "gemini",
    model: GEMINI_MODEL,
    score: Math.min(100, Number(parsed.score) || 0),
    verdict: parsed.verdict || "clean_or_unclear",
    summary: parsed.summary || "",
    indicators: parsed.indicators || [],
    hits: (parsed.indicators || []).map((x) => ({ source: "gemini", keyword: String(x) })),
  };
}

async function grokTriage({ events = [], screenshots = [] }) {
  if (!XAI_API_KEY) return null;

  const textParts = events.slice(0, 25).map((e, i) =>
    `Event${i + 1}: pkg=${e.packageName || "?"} title=${e.title || ""} text=${e.text || ""} flags=${(e.riskKeywordHits || []).join(",")}`
  );
  const shotParts = screenshots.slice(0, 5).map((s, i) =>
    `Shot${i + 1}: hash=${s.hash || "none"} note=${s.note || ""} hasImage=${!!s.imageBase64}`
  );

  const content = [
    {
      type: "text",
      text:
        "You are a security triage assistant for a consent-based mobile integrity system. " +
        "Decide if popup/notification text suggests cheating panels, injectors, ESP/aimbot overlays for mobile games. " +
        "Do NOT assume guilt from normal game UI. Reply JSON only: " +
        '{"score":0-100,"verdict":"clean_or_unclear|suspicious|likely_cheat_ui","summary":"...","indicators":["..."]}\n\n' +
        textParts.join("\n") + "\n" + shotParts.join("\n"),
    },
  ];

  // Attach at most 2 images if present (data URL)
  let imgs = 0;
  for (const s of screenshots) {
    if (s.imageBase64 && imgs < 2) {
      const mime = s.mime || "image/png";
      const b64 = String(s.imageBase64).replace(/^data:image\/\w+;base64,/, "");
      content.push({
        type: "image_url",
        image_url: { url: `data:${mime};base64,${b64}` },
      });
      imgs++;
    }
  }

  const body = {
    model: XAI_MODEL,
    messages: [
      { role: "system", content: "Return only valid JSON. No markdown." },
      { role: "user", content },
    ],
    temperature: 0.2,
  };

  const r = await fetch(`${XAI_BASE}/chat/completions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${XAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  if (!r.ok) {
    const err = j?.error?.message || j?.error || JSON.stringify(j).slice(0, 200);
    throw new Error(`xAI error: ${err}`);
  }
  const raw = j.choices?.[0]?.message?.content || "";
  let parsed;
  try {
    const m = raw.match(/\{[\s\S]*\}/);
    parsed = JSON.parse(m ? m[0] : raw);
  } catch {
    parsed = {
      score: 0,
      verdict: "clean_or_unclear",
      summary: raw.slice(0, 400),
      indicators: [],
    };
  }
  return {
    engine: IS_GROQ ? "groq" : "xai",
    model: XAI_MODEL,
    score: Math.min(100, Number(parsed.score) || 0),
    verdict: parsed.verdict || "clean_or_unclear",
    summary: parsed.summary || "",
    indicators: parsed.indicators || [],
    hits: (parsed.indicators || []).map((x) => ({ source: "grok", keyword: String(x) })),
  };
}

app.get("/ready", (_req, res) => {
  res.json({ ready: true, service: typeof SERVICE !== "undefined" ? SERVICE : "ok" });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: SERVICE,
    phase: 8,
    grokConfigured: !!XAI_API_KEY,
    llmProvider: IS_GROQ ? "groq" : (XAI_API_KEY ? "xai" : null),
    exploriumConfigured: !!EXPLORIUM_API_KEY,
    geminiConfigured: !!GEMINI_API_KEY,
    model: XAI_API_KEY ? XAI_MODEL : null,
    time: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
  });
});

app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    phase: 8,
    group: "D — AI Workspace light",
    grokConfigured: !!XAI_API_KEY,
    llmProvider: IS_GROQ ? "groq" : (XAI_API_KEY ? "xai" : null),
    exploriumConfigured: !!EXPLORIUM_API_KEY,
    geminiConfigured: !!GEMINI_API_KEY,
    endpoints: [
      "POST /v1/triage/popup",
      "POST /v1/triage/text",
      "GET  /v1/triage/:id",
      "GET  /v1/triage/mine",
      "GET  /v1/ai/status",
    ],
  });
});

app.get("/v1/ai/status", (_req, res) => {
  ok(res, {
    grokConfigured: !!XAI_API_KEY,
    llmProvider: IS_GROQ ? "groq" : (XAI_API_KEY ? "xai" : null),
    exploriumConfigured: !!EXPLORIUM_API_KEY,
    geminiConfigured: !!GEMINI_API_KEY,
    model: XAI_API_KEY ? XAI_MODEL : null,
    base: XAI_API_KEY ? XAI_BASE : null,
    fallback: "heuristic",
  });
});

/**
 * Main entry used by dark-b forward-ai
 */
app.post("/v1/triage/popup", auth, async (req, res) => {
  const events = Array.isArray(req.body?.events) ? req.body.events : [];
  const screenshots = Array.isArray(req.body?.screenshots) ? req.body.screenshots : [];
  const sessionId = req.body?.sessionId ? String(req.body.sessionId) : null;

  let result;
  let engineUsed = "heuristic";
  try {
    if (GEMINI_API_KEY) {
      result = await geminiTriage({ events, screenshots });
      engineUsed = "gemini";
    } else if (XAI_API_KEY) {
      result = await grokTriage({ events, screenshots });
      engineUsed = IS_GROQ ? "groq" : "xai";
    }
  } catch (e) {
    result = heuristicTriage({ events, screenshots });
    result.llmError = e.message;
    engineUsed = "heuristic_fallback";
  }
  if (!result) result = heuristicTriage({ events, screenshots });

  const db = load(JOBS, { items: [] });
  const id = randomBytes(8).toString("hex");
  const row = {
    id,
    type: "popup",
    sessionId,
    userId: req.user.sub,
    engine: engineUsed,
    result,
    eventCount: events.length,
    screenshotCount: screenshots.length,
    createdAt: new Date().toISOString(),
  };
  db.items.unshift(row);
  db.items = db.items.slice(0, 200);
  save(JOBS, db);

  const scanId = req.body?.scanId || null;
  const record = { id, engine: engineUsed, result, scanId, at: new Date().toISOString(), user: req.user?.sub };
  persistTriage(record).catch(() => {});
  // AI done → purge heavy scan payload from server+GitHub (keep DB light)
  if (scanId) {
    const authHeader = req.headers.authorization || "";
    const tok = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    requestScanCleanup(scanId, tok).catch(() => {});
  }
  return ok(res, { triageId: id, engine: engineUsed, result, scanCleanup: Boolean(scanId) });
});

app.post("/v1/triage/text", auth, async (req, res) => {
  const text = String(req.body?.text || "").slice(0, 4000);
  if (!text) return fail(res, 400, "bad_request", "text required");
  const events = [{ title: "", text, packageName: req.body?.packageName || "" }];
  let result;
  let engineUsed = "heuristic";
  try {
    if (GEMINI_API_KEY) {
      result = await geminiTriage({ events, screenshots: [] });
      engineUsed = "gemini";
    } else if (XAI_API_KEY) {
      result = await grokTriage({ events, screenshots: [] });
      engineUsed = IS_GROQ ? "groq" : "xai";
    }
  } catch (e) {
    result = heuristicTriage({ events, screenshots: [] });
    result.llmError = e.message;
    engineUsed = "heuristic_fallback";
  }
  if (!result) result = heuristicTriage({ events, screenshots: [] });

  const db = load(JOBS, { items: [] });
  const id = randomBytes(8).toString("hex");
  db.items.unshift({
    id,
    type: "text",
    userId: req.user.sub,
    engine: engineUsed,
    result,
    createdAt: new Date().toISOString(),
  });
  db.items = db.items.slice(0, 200);
  save(JOBS, db);
  const scanId = req.body?.scanId || null;
  const record = { id, engine: engineUsed, result, scanId, at: new Date().toISOString(), user: req.user?.sub };
  persistTriage(record).catch(() => {});
  // AI done → purge heavy scan payload from server+GitHub (keep DB light)
  if (scanId) {
    const authHeader = req.headers.authorization || "";
    const tok = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    requestScanCleanup(scanId, tok).catch(() => {});
  }
  return ok(res, { triageId: id, engine: engineUsed, result, scanCleanup: Boolean(scanId) });
});

app.get("/v1/triage/:id", auth, (req, res) => {
  const db = load(JOBS, { items: [] });
  const row = db.items.find((x) => x.id === req.params.id);
  if (!row) return fail(res, 404, "not_found", "triage not found");
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your triage");
  }
  return ok(res, { triage: row });
});

app.get("/v1/triage/mine", auth, (req, res) => {
  const db = load(JOBS, { items: [] });
  const list = db.items
    .filter((x) => x.userId === req.user.sub || req.user.role === "admin")
    .slice(0, 50)
    .map((x) => ({
      id: x.id,
      type: x.type,
      engine: x.engine,
      verdict: x.result?.verdict,
      score: x.result?.score,
      createdAt: x.createdAt,
    }));
  return ok(res, { items: list });
});


app.get("/v1/ai/workspace", (_req, res) => {
  ok(res, {
    name: "Div Integrity AI Workspace",
    mission: "Passive mobile integrity triage for tournament anti-cheat. Never modify games. Never inject processes. Never claim Free Fire was altered.",
    rules: [
      "No auth / no consent → no scan advice that enables abuse",
      "Passive only: read signals, score, explain",
      "Heavy APK/decompile work ONLY via GitHub Actions repo div-integrity-jobs",
      "All file content for AI must be TEXT (.txt). Zip/apk must be converted before analysis storage",
      "Do not treat 'Div scanner is running' notification as malware",
      "OTP and secrets never log in full in outputs",
    ],
    roles: {
      admin: "Approve/remove owners, lock panel HTML, see all owners/players",
      owner: "Referral ds_ff/+24 chars, players list, request scans, view text results",
      player: "Hidden notification app, permissions, join via referral",
    },
    endpoints: {
      triageText: "POST /v1/triage/text",
      triagePopup: "POST /v1/triage/popup",
      status: "GET /v1/ai/status",
      heavyJob: "POST https://div-ai-heavy.onrender.com/v1/jobs/apk",
    },
    models: {
      primary: "gemini (if GEMINI_API_KEY)",
      secondary: "groq/xai (if configured)",
      fallback: "heuristic keywords",
    },
    github: {
      dataRepo: "web-coder-lab/div-integrity-data",
      jobsRepo: "web-coder-lab/div-integrity-jobs",
      workflow: "analyze.yml",
    },
    outputFormat: {
      triage: "{ score 0-100, verdict clean_or_unclear|suspicious|likely_cheat_ui, summary, indicators[] }",
      heavy: "callback POST /v1/jobs/:id/result with engine,score,verdict,findings,summary",
    },
  });
});

app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 ${SERVICE} Phase 8 on :${PORT} grok=${!!XAI_API_KEY}`);
});