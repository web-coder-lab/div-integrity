/**
 * Phase 7 — div-scan-dark-b
 * Notification listener presence + popup screenshot META intake
 * Does NOT scrape OTP content. Forwards summary to dark-a / ai-light.
 * Passive / disclosed use only.
 */
import express from "express";
import cors from "cors";
import { createHmac, randomBytes, createHash } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { rateLimit, securityHeaders, applySecurity, pathFirewall } from "./hardening.js";

const app = express();
app.set("trust proxy", 1);
applySecurity(app);
app.use(cors({ origin: true }));
app.use(express.json({ limit: "6mb" }));

const PORT = process.env.PORT || 3000;
const SERVICE = "div-scan-dark-b";
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-div-auth";
const DARK_A_URL = (process.env.DARK_A_URL || "https://div-scan-dark-a.onrender.com").replace(/\/$/, "");
const AI_LIGHT_URL = (process.env.AI_LIGHT_URL || "https://div-ai-light.onrender.com").replace(/\/$/, "");
const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });
const STORE = join(DATA, "popups.json");

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
  const payload = verifyJwt(token);
  if (!payload) return fail(res, 401, "unauthorized", "valid token required");
  req.user = payload;
  next();
}

/** Redact obvious OTP-like patterns from any text client mistakenly sends */
function redactSensitive(text) {
  if (!text || typeof text !== "string") return "";
  let t = text.slice(0, 500);
  t = t.replace(/\b\d{4,8}\b/g, "[redacted]");
  t = t.replace(/(otp|code|password|pin)\s*[:#-]?\s*\w+/gi, "$1:[redacted]");
  return t;
}

app.get("/ready", (_req, res) => {
  res.json({ ready: true, service: typeof SERVICE !== "undefined" ? SERVICE : "ok" });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: SERVICE,
    phase: 7,
    role: "popup-notification-intake",
    time: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
  });
});

app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    phase: 7,
    group: "C — Dark Observe B",
    policy: {
      otpScraping: false,
      notificationContent: "redacted_or_presence_only",
      gameCross: false,
    },
    endpoints: [
      "POST /v1/popup/session",
      "POST /v1/popup/:sessionId/event",
      "POST /v1/popup/:sessionId/screenshot",
      "GET  /v1/popup/:sessionId",
      "POST /v1/popup/:sessionId/forward-dark-a",
      "POST /v1/popup/:sessionId/forward-ai",
      "GET  /v1/popup/mine",
    ],
  });
});

/** Open popup/notification capture session bound to observeId optional */
app.post("/v1/popup/session", auth, (req, res) => {
  const observeId = req.body?.observeId ? String(req.body.observeId) : null;
  const deviceId = req.body?.deviceId ? String(req.body.deviceId) : null;
  const db = load(STORE, { sessions: [] });
  const id = randomBytes(8).toString("hex");
  const row = {
    id,
    observeId,
    deviceId,
    userId: req.user.sub,
    status: "open",
    events: [],
    screenshots: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.sessions.unshift(row);
  db.sessions = db.sessions.slice(0, 200);
  save(STORE, db);
  return ok(res, { session: { id: row.id, status: row.status, observeId } }, 201);
});

/**
 * Notification / popup event — presence + safe labels only
 * body: {
 *   source: "notification_listener" | "accessibility_window" | "media_projection",
 *   packageName, title?, text?, category?, isOngoing?
 * }
 */
app.post("/v1/popup/:sessionId/event", auth, (req, res) => {
  const db = load(STORE, { sessions: [] });
  const idx = db.sessions.findIndex((s) => s.id === req.params.sessionId);
  if (idx < 0) return fail(res, 404, "not_found", "session not found");
  const row = db.sessions[idx];
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }
  if (row.status !== "open") return fail(res, 400, "closed", "session closed");

  const source = String(req.body?.source || "unknown").slice(0, 64);
  const packageName = String(req.body?.packageName || "unknown").slice(0, 180);
  const title = redactSensitive(String(req.body?.title || ""));
  const text = redactSensitive(String(req.body?.text || ""));
  const category = String(req.body?.category || "").slice(0, 64);

  // Flag possible panel/hack keywords in redacted-safe labels (not OTP)
  const blob = `${title} ${text} ${packageName}`.toLowerCase();
  const riskKeywords = ["aimbot", "esp", "hack", "mod menu", "injector", "floating", "bypass", "panel"];
  const hits = riskKeywords.filter((k) => blob.includes(k));

  const event = {
    id: randomBytes(4).toString("hex"),
    source,
    packageName,
    title,
    text,
    category,
    isOngoing: !!req.body?.isOngoing,
    riskKeywordHits: hits,
    at: new Date().toISOString(),
  };
  row.events.push(event);
  if (row.events.length > 300) row.events = row.events.slice(-300);
  row.updatedAt = new Date().toISOString();
  db.sessions[idx] = row;
  save(STORE, db);

  return ok(res, { eventId: event.id, riskKeywordHits: hits, eventCount: row.events.length });
});

/**
 * Screenshot meta + optional small base64 preview (not required)
 * Prefer hash + size + dimensions; full image can go to AI later
 * body: { hash?, width?, height?, mime?, note?, imageBase64? }
 */
app.post("/v1/popup/:sessionId/screenshot", auth, (req, res) => {
  const db = load(STORE, { sessions: [] });
  const idx = db.sessions.findIndex((s) => s.id === req.params.sessionId);
  if (idx < 0) return fail(res, 404, "not_found", "session not found");
  const row = db.sessions[idx];
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }
  if (row.status !== "open") return fail(res, 400, "closed", "session closed");

  let imageBase64 = req.body?.imageBase64 ? String(req.body.imageBase64) : null;
  if (imageBase64 && imageBase64.length > 1_500_000) {
    return fail(res, 400, "too_large", "image too large; send hash/meta only or smaller frame");
  }
  const hash = req.body?.hash
    ? String(req.body.hash)
    : imageBase64
      ? createHash("sha256").update(imageBase64).digest("hex")
      : null;

  const shot = {
    id: randomBytes(4).toString("hex"),
    hash,
    width: req.body?.width ? Number(req.body.width) : null,
    height: req.body?.height ? Number(req.body.height) : null,
    mime: req.body?.mime ? String(req.body.mime).slice(0, 40) : null,
    note: redactSensitive(String(req.body?.note || "")).slice(0, 200),
    // store image only if provided (ephemeral analysis); large arrays capped
    hasImage: !!imageBase64,
    imageBase64: imageBase64 || undefined,
    at: new Date().toISOString(),
  };
  row.screenshots.push(shot);
  if (row.screenshots.length > 40) {
    // drop oldest images to save disk
    row.screenshots = row.screenshots.slice(-40).map((s, i, arr) => {
      if (i < arr.length - 5) return { ...s, imageBase64: undefined };
      return s;
    });
  }
  row.updatedAt = new Date().toISOString();
  db.sessions[idx] = row;
  save(STORE, db);

  return ok(res, {
    screenshotId: shot.id,
    hash: shot.hash,
    hasImage: shot.hasImage,
    screenshotCount: row.screenshots.length,
  }, 201);
});

app.get("/v1/popup/:sessionId", auth, (req, res) => {
  const db = load(STORE, { sessions: [] });
  const row = db.sessions.find((s) => s.id === req.params.sessionId);
  if (!row) return fail(res, 404, "not_found", "session not found");
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }
  // strip images from default get unless ?includeImages=1
  const include = req.query.includeImages === "1";
  const out = {
    ...row,
    screenshots: row.screenshots.map((s) =>
      include ? s : { ...s, imageBase64: undefined }
    ),
  };
  return ok(res, { session: out });
});

/** Forward popup_screenshot_meta signals into dark-a observe session */
app.post("/v1/popup/:sessionId/forward-dark-a", auth, async (req, res) => {
  const db = load(STORE, { sessions: [] });
  const row = db.sessions.find((s) => s.id === req.params.sessionId);
  if (!row) return fail(res, 404, "not_found", "session not found");
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }
  const observeId = String(req.body?.observeId || row.observeId || "");
  if (!observeId) return fail(res, 400, "bad_request", "observeId required");

  const signals = [
    ...row.events.slice(-20).map((e) => ({
      type: "notification_listener_presence",
      payload: {
        packageName: e.packageName,
        riskKeywordHits: e.riskKeywordHits,
        source: e.source,
      },
    })),
    ...row.screenshots.slice(-10).map((s) => ({
      type: "popup_screenshot_meta",
      payload: { hash: s.hash, width: s.width, height: s.height, note: s.note },
    })),
  ];

  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  try {
    const r = await fetch(`${DARK_A_URL}/v1/observe/${observeId}/signals`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ signals }),
    });
    const j = await r.json();
    if (!r.ok) return fail(res, r.status, j?.error?.code || "forward_failed", j?.error?.message || "fail");
    row.lastForwardDarkA = new Date().toISOString();
    save(STORE, db);
    return ok(res, { forwarded: true, darkA: j.data });
  } catch (e) {
    return fail(res, 502, "dark_a_unreachable", e.message || "unreachable");
  }
});

/** Queue for AI light triage (Phase 8 will consume fully) */
app.post("/v1/popup/:sessionId/forward-ai", auth, async (req, res) => {
  const db = load(STORE, { sessions: [] });
  const row = db.sessions.find((s) => s.id === req.params.sessionId);
  if (!row) return fail(res, 404, "not_found", "session not found");
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const payload = {
    sessionId: row.id,
    events: row.events.slice(-30),
    screenshots: row.screenshots.slice(-5).map((s) => ({
      id: s.id,
      hash: s.hash,
      note: s.note,
      hasImage: s.hasImage,
      imageBase64: s.imageBase64,
    })),
  };
  try {
    const r = await fetch(`${AI_LIGHT_URL}/v1/triage/popup`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    let j;
    try { j = JSON.parse(text); } catch { j = { raw: text }; }
    if (!r.ok) {
      // Phase 8 may not be deployed yet — store locally as queued
      row.aiQueue = row.aiQueue || [];
      row.aiQueue.push({ at: new Date().toISOString(), payload: { sessionId: row.id, eventCount: row.events.length } });
      save(STORE, db);
      return ok(res, {
        queuedLocally: true,
        reason: "ai-light not ready or error",
        status: r.status,
        body: j,
      });
    }
    row.lastForwardAi = new Date().toISOString();
    save(STORE, db);
    return ok(res, { forwarded: true, ai: j.data || j });
  } catch (e) {
    row.aiQueue = row.aiQueue || [];
    row.aiQueue.push({ at: new Date().toISOString(), error: e.message });
    save(STORE, db);
    return ok(res, { queuedLocally: true, reason: e.message });
  }
});

app.get("/v1/popup/mine", auth, (req, res) => {
  const db = load(STORE, { sessions: [] });
  const list = db.sessions
    .filter((s) => s.userId === req.user.sub || req.user.role === "admin")
    .slice(0, 50)
    .map((s) => ({
      id: s.id,
      status: s.status,
      observeId: s.observeId,
      eventCount: s.events?.length || 0,
      screenshotCount: s.screenshots?.length || 0,
      createdAt: s.createdAt,
    }));
  return ok(res, { sessions: list });
});

app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 ${SERVICE} Phase 7 on :${PORT}`);
});