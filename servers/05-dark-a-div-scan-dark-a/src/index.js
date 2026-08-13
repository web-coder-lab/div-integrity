/**
 * Phase 6 — div-scan-dark-a
 * Dark Observe when Free Fire (or target package) is ON
 * READ-ONLY: presence, thresholds, no inject / no network block / no game modify
 */
import express from "express";
import cors from "cors";
import { createHmac, randomBytes } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { rateLimit, securityHeaders, applySecurity, pathFirewall } from "./hardening.js";

const app = express();
app.set("trust proxy", 1);
applySecurity(app);
app.use(cors({ origin: true }));
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const SERVICE = "div-scan-dark-a";
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-div-auth";
const LINK_URL = (process.env.LINK_URL || "https://div-user-link.onrender.com").replace(/\/$/, "");
const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });
const OBS = join(DATA, "observe.json");

/** Packages we treat as "match context" — presence only */
const DEFAULT_WATCH = [
  "com.dts.freefireth",
  "com.dts.freefiremax",
  "com.garena.game.kgvn",
];

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
  if (!payload) return fail(res, 401, "unauthorized", "valid token required — no auth, no observe");
  req.user = payload;
  next();
}

async function canScan(ownerToken, userId) {
  try {
    const r = await fetch(`${LINK_URL}/v1/policy/can-scan?userId=${encodeURIComponent(userId)}`, {
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    const j = await r.json();
    return j?.data?.allowed === true;
  } catch {
    return null;
  }
}

const BLOCKED = new Set([
  "process_inject", "memory_write", "network_block", "game_hook",
  "packet_drop", "overlay_on_game", "input_inject",
]);

app.get("/ready", (_req, res) => {
  res.json({ ready: true, service: typeof SERVICE !== "undefined" ? SERVICE : "ok" });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: SERVICE,
    phase: 6,
    mode: "dark_observe",
    intensity: "100000",
    time: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
  });
});

app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    phase: 6,
    group: "C — Dark Observe",
    policy: {
      freeFireCross: false,
      processInject: false,
      networkBlock: false,
      readOnly: true,
      note: "Activates when watch package presence is reported ON. Does not modify the game.",
    },
    watchPackages: DEFAULT_WATCH,
    endpoints: [
      "POST /v1/observe/start",
      "POST /v1/observe/:id/presence",
      "POST /v1/observe/:id/signals",
      "POST /v1/observe/:id/complete",
      "GET  /v1/observe/:id",
      "GET  /v1/observe/mine",
    ],
  });
});

app.post("/v1/observe/start", auth, async (req, res) => {
  const targetUserId = String(req.body?.targetUserId || req.user.sub);
  const deviceId = req.body?.deviceId ? String(req.body.deviceId) : null;
  const watchPackages = Array.isArray(req.body?.watchPackages) && req.body.watchPackages.length
    ? req.body.watchPackages.map(String).slice(0, 20)
    : DEFAULT_WATCH;

  if (targetUserId !== req.user.sub) {
    if (!["owner", "admin"].includes(req.user.role)) {
      return fail(res, 403, "forbidden", "only owner/admin can observe another user");
    }
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const allowed = await canScan(token, targetUserId);
    if (allowed === false) return fail(res, 403, "not_allowed", "not linked or no consent");
    if (allowed === null && req.user.role !== "admin") {
      return fail(res, 503, "link_unavailable", "link service unavailable");
    }
  }

  const db = load(OBS, { items: [] });
  const id = randomBytes(8).toString("hex");
  const row = {
    id,
    mode: "dark_observe",
    intensity: "100000",
    status: "waiting_presence", // until FF/watch package reported on
    targetUserId,
    deviceId,
    requestedBy: req.user.sub,
    watchPackages,
    freeFireRunning: false,
    presenceEvents: [],
    signals: [],
    score: null,
    verdict: null,
    policy: {
      readOnly: true,
      noGameModify: true,
      noProcessInject: true,
      noNetworkBlock: true,
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.items.unshift(row);
  db.items = db.items.slice(0, 200);
  save(OBS, db);

  return ok(res, {
    observe: {
      id: row.id,
      status: row.status,
      mode: row.mode,
      watchPackages: row.watchPackages,
      policy: row.policy,
    },
  }, 201);
});

/**
 * Client reports package presence (read from device inventory / usage stats)
 * body: { runningPackages: string[], foreground?: string }
 */
app.post("/v1/observe/:id/presence", auth, (req, res) => {
  const db = load(OBS, { items: [] });
  const idx = db.items.findIndex((x) => x.id === req.params.id);
  if (idx < 0) return fail(res, 404, "not_found", "observe session not found");
  const row = db.items[idx];
  if (row.requestedBy !== req.user.sub && row.targetUserId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }
  if (row.status === "completed" || row.status === "aborted") {
    return fail(res, 400, "closed", "session closed");
  }

  const running = Array.isArray(req.body?.runningPackages)
    ? req.body.runningPackages.map(String)
    : [];
  const foreground = req.body?.foreground ? String(req.body.foreground) : null;
  const hit = row.watchPackages.filter((p) => running.includes(p) || foreground === p);
  const on = hit.length > 0;

  row.presenceEvents.push({
    at: new Date().toISOString(),
    runningCount: running.length,
    foreground,
    watchHit: hit,
    freeFireRunning: on,
  });
  if (row.presenceEvents.length > 100) row.presenceEvents = row.presenceEvents.slice(-100);

  row.freeFireRunning = on;
  if (on && row.status === "waiting_presence") {
    row.status = "observing";
    row.observingSince = new Date().toISOString();
  }
  if (!on && row.status === "observing") {
    row.status = "waiting_presence";
  }
  row.updatedAt = new Date().toISOString();
  db.items[idx] = row;
  save(OBS, db);

  return ok(res, {
    id: row.id,
    status: row.status,
    freeFireRunning: row.freeFireRunning,
    watchHit: hit,
    message: on
      ? "Watch package ON — dark observe active (read-only)"
      : "Watch package OFF — waiting (no aggressive collect)",
  });
});

/**
 * Dark signals — only accepted while observing (FF on)
 * Stricter allowlist than deep mode
 */
app.post("/v1/observe/:id/signals", auth, (req, res) => {
  const db = load(OBS, { items: [] });
  const idx = db.items.findIndex((x) => x.id === req.params.id);
  if (idx < 0) return fail(res, 404, "not_found", "observe session not found");
  const row = db.items[idx];
  if (row.requestedBy !== req.user.sub && row.targetUserId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }
  if (row.status !== "observing") {
    return fail(res, 400, "not_observing", "start presence with watch package ON first");
  }

  const incoming = Array.isArray(req.body?.signals) ? req.body.signals : [];
  if (!incoming.length) return fail(res, 400, "bad_request", "signals required");
  if (incoming.length > 50) return fail(res, 400, "too_many", "max 50 per batch in dark mode");

  const allowed = new Set([
    "background_service_near_game",
    "overlay_presence",
    "accessibility_presence",
    "notification_listener_presence",
    "suspicious_package_running",
    "virtual_display",
    "root_heuristic",
    "popup_screenshot_meta", // meta only here; binary goes to dark-b / ai later
  ]);

  const accepted = [];
  const rejected = [];
  for (const sig of incoming) {
    const type = String(sig?.type || "").slice(0, 64);
    if (BLOCKED.has(type) || !allowed.has(type)) {
      rejected.push({ type, reason: "not_allowed_in_dark_observe" });
      continue;
    }
    row.signals.push({
      type,
      payload: sig.payload ?? {},
      at: new Date().toISOString(),
    });
    accepted.push(type);
  }
  if (row.signals.length > 400) row.signals = row.signals.slice(-400);
  row.updatedAt = new Date().toISOString();
  db.items[idx] = row;
  save(OBS, db);

  return ok(res, {
    id: row.id,
    accepted: accepted.length,
    rejected,
    signalCount: row.signals.length,
    status: row.status,
  });
});

app.post("/v1/observe/:id/complete", auth, (req, res) => {
  const db = load(OBS, { items: [] });
  const idx = db.items.findIndex((x) => x.id === req.params.id);
  if (idx < 0) return fail(res, 404, "not_found", "observe session not found");
  const row = db.items[idx];
  if (row.requestedBy !== req.user.sub && row.targetUserId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }

  let risk = 0;
  const findings = [];
  for (const s of row.signals) {
    if (s.type === "suspicious_package_running") { risk += 20; findings.push("suspicious_package"); }
    if (s.type === "overlay_presence") { risk += 15; findings.push("overlay"); }
    if (s.type === "accessibility_presence") { risk += 12; findings.push("accessibility"); }
    if (s.type === "notification_listener_presence") { risk += 10; findings.push("notif_listener"); }
    if (s.type === "virtual_display") { risk += 18; findings.push("virtual_display"); }
    if (s.type === "root_heuristic" && s.payload?.suspicious) { risk += 20; findings.push("root"); }
    if (s.type === "background_service_near_game") { risk += 10; findings.push("bg_near_game"); }
    if (s.type === "popup_screenshot_meta") { risk += 5; findings.push("popup_meta"); }
  }
  // Presence without extra signals still notes context
  if (row.freeFireRunning) findings.push("watch_package_was_on");
  risk = Math.min(100, risk);
  const verdict = risk >= 70 ? "high_risk" : risk >= 35 ? "review" : "clean";

  row.status = "completed";
  row.score = risk;
  row.verdict = verdict;
  row.findings = [...new Set(findings)];
  row.completedAt = new Date().toISOString();
  row.updatedAt = row.completedAt;
  db.items[idx] = row;
  save(OBS, db);

  return ok(res, {
    id: row.id,
    status: row.status,
    score: row.score,
    verdict: row.verdict,
    findings: row.findings,
    signalCount: row.signals.length,
    policy: row.policy,
  });
});

app.get("/v1/observe/:id", auth, (req, res) => {
  const db = load(OBS, { items: [] });
  const row = db.items.find((x) => x.id === req.params.id);
  if (!row) return fail(res, 404, "not_found", "not found");
  if (row.requestedBy !== req.user.sub && row.targetUserId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your session");
  }
  return ok(res, { observe: row });
});

app.get("/v1/observe/mine", auth, (req, res) => {
  const db = load(OBS, { items: [] });
  const list = db.items
    .filter((x) => x.requestedBy === req.user.sub || x.targetUserId === req.user.sub || req.user.role === "admin")
    .slice(0, 50)
    .map((x) => ({
      id: x.id,
      status: x.status,
      freeFireRunning: x.freeFireRunning,
      score: x.score,
      verdict: x.verdict,
      signalCount: x.signals?.length || 0,
      createdAt: x.createdAt,
    }));
  return ok(res, { items: list });
});

app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 ${SERVICE} Phase 6 dark-observe on :${PORT}`);
});