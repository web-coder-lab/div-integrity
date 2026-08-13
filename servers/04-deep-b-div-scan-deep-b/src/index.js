/**
 * Phase 5 — div-scan-deep-b
 * Secondary deep worker: bulk signal ingest, normalize, risk tags
 * Works with div-scan-deep-a (orchestrator). Passive only.
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
app.use(express.json({ limit: "4mb" }));

const PORT = process.env.PORT || 3000;
const SERVICE = "div-scan-deep-b";
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-div-auth";
const DEEP_A_URL = (process.env.DEEP_A_URL || "https://div-scan-deep-a.onrender.com").replace(/\/$/, "");
const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });
const INGEST = join(DATA, "ingest.json");

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
  if (!payload) return fail(res, 401, "unauthorized", "valid token required — no auth, no scan");
  req.user = payload;
  next();
}

const BLOCKED = new Set(["process_inject", "memory_write", "network_block", "game_hook", "packet_drop"]);

/** Normalize + tag a single signal */
function normalizeSignal(raw) {
  const type = String(raw?.type || "unknown").slice(0, 64).toLowerCase();
  if (BLOCKED.has(type)) return { error: "policy_violation", type };
  const payload = raw?.payload && typeof raw.payload === "object" ? raw.payload : {};
  const tags = [];
  let riskDelta = 0;

  switch (type) {
    case "root_heuristic":
      if (payload.suspicious || payload.suBinary || payload.magisk) {
        tags.push("root"); riskDelta += 25;
      }
      break;
    case "package_list":
      tags.push("inventory");
      if ((payload.count || 0) > 400) tags.push("large_inventory");
      break;
    case "sideloaded_apps":
      if ((payload.count || 0) > 0) { tags.push("sideload"); riskDelta += 12; }
      break;
    case "overlay":
      if ((payload.count || 0) > 0) { tags.push("overlay"); riskDelta += 8; }
      break;
    case "accessibility_presence":
      if ((payload.count || 0) > 0) { tags.push("a11y"); riskDelta += 8; }
      break;
    case "notification_listener_presence":
      if ((payload.count || 0) > 0) { tags.push("notif_listener"); riskDelta += 6; }
      break;
    case "integrity_token":
      tags.push("play_integrity");
      if (payload.deviceIntegrity === "MEETS_DEVICE_INTEGRITY") riskDelta -= 15;
      else if (payload.deviceIntegrity) riskDelta += 20;
      break;
    case "vpn_flow_meta":
      tags.push("network_observe");
      break;
    case "file_sample_hash":
      tags.push("sample");
      break;
    default:
      tags.push("generic");
  }

  return {
    type,
    payload,
    tags,
    riskDelta,
    at: new Date().toISOString(),
  };
}

app.get("/ready", (_req, res) => {
  res.json({ ready: true, service: typeof SERVICE !== "undefined" ? SERVICE : "ok" });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: SERVICE,
    phase: 5,
    role: "deep-signal-worker",
    time: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
  });
});

app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    phase: 5,
    group: "B — Deep Scan worker",
    policy: "Passive signal normalize only. No game cross.",
    endpoints: [
      "POST /v1/ingest",
      "POST /v1/ingest/batch",
      "GET  /v1/ingest/:id",
      "POST /v1/ingest/:id/forward",
      "GET  /v1/ingest/mine",
    ],
    deepA: DEEP_A_URL,
  });
});

/**
 * Create ingest session for a scan (or standalone collect)
 * body: { scanId?, deviceId? }
 */
app.post("/v1/ingest", auth, (req, res) => {
  const scanId = req.body?.scanId ? String(req.body.scanId) : null;
  const deviceId = req.body?.deviceId ? String(req.body.deviceId) : null;
  const db = load(INGEST, { items: [] });
  const id = randomBytes(8).toString("hex");
  const row = {
    id,
    scanId,
    deviceId,
    userId: req.user.sub,
    status: "open",
    signals: [],
    riskSum: 0,
    tags: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.items.unshift(row);
  db.items = db.items.slice(0, 300);
  save(INGEST, db);
  return ok(res, { ingest: { id: row.id, status: row.status, scanId: row.scanId } }, 201);
});

/**
 * Batch signals into ingest
 * body: { signals: [{type, payload}] }
 */
app.post("/v1/ingest/:id/batch", auth, (req, res) => {
  const db = load(INGEST, { items: [] });
  const idx = db.items.findIndex((x) => x.id === req.params.id);
  if (idx < 0) return fail(res, 404, "not_found", "ingest not found");
  const row = db.items[idx];
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your ingest");
  }
  if (row.status !== "open" && row.status !== "collecting") {
    return fail(res, 400, "closed", "ingest closed");
  }

  const incoming = Array.isArray(req.body?.signals) ? req.body.signals : [];
  if (!incoming.length) return fail(res, 400, "bad_request", "signals required");
  if (incoming.length > 200) return fail(res, 400, "too_many", "max 200 per batch");

  const accepted = [];
  const rejected = [];
  for (const raw of incoming) {
    const n = normalizeSignal(raw);
    if (n.error) {
      rejected.push({ type: n.type, reason: n.error });
      continue;
    }
    row.signals.push(n);
    row.riskSum += n.riskDelta;
    for (const t of n.tags) if (!row.tags.includes(t)) row.tags.push(t);
    accepted.push(n.type);
  }
  if (row.signals.length > 800) row.signals = row.signals.slice(-800);
  row.status = "collecting";
  row.updatedAt = new Date().toISOString();
  db.items[idx] = row;
  save(INGEST, db);

  return ok(res, {
    id: row.id,
    accepted: accepted.length,
    rejected,
    signalCount: row.signals.length,
    riskSum: Math.max(0, Math.min(100, row.riskSum)),
    tags: row.tags,
  });
});

// alias
app.post("/v1/ingest/batch", auth, (req, res) => {
  // if body.ingestId provided
  req.params = { id: String(req.body?.ingestId || "") };
  if (!req.params.id) return fail(res, 400, "bad_request", "ingestId required");
  // reuse handler by re-calling logic — simple redirect style
  const db = load(INGEST, { items: [] });
  const idx = db.items.findIndex((x) => x.id === req.params.id);
  if (idx < 0) return fail(res, 404, "not_found", "ingest not found");
  const row = db.items[idx];
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your ingest");
  }
  const incoming = Array.isArray(req.body?.signals) ? req.body.signals : [];
  if (!incoming.length) return fail(res, 400, "bad_request", "signals required");
  const accepted = [];
  const rejected = [];
  for (const raw of incoming) {
    const n = normalizeSignal(raw);
    if (n.error) { rejected.push({ type: n.type, reason: n.error }); continue; }
    row.signals.push(n);
    row.riskSum += n.riskDelta;
    for (const t of n.tags) if (!row.tags.includes(t)) row.tags.push(t);
    accepted.push(n.type);
  }
  row.status = "collecting";
  row.updatedAt = new Date().toISOString();
  db.items[idx] = row;
  save(INGEST, db);
  return ok(res, { id: row.id, accepted: accepted.length, rejected, signalCount: row.signals.length, riskSum: row.riskSum, tags: row.tags });
});

app.get("/v1/ingest/:id", auth, (req, res) => {
  const db = load(INGEST, { items: [] });
  const row = db.items.find((x) => x.id === req.params.id);
  if (!row) return fail(res, 404, "not_found", "ingest not found");
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your ingest");
  }
  return ok(res, { ingest: row });
});

/**
 * Forward normalized signals to deep-a scan
 * body: { scanId } optional override
 */
app.post("/v1/ingest/:id/forward", auth, async (req, res) => {
  const db = load(INGEST, { items: [] });
  const row = db.items.find((x) => x.id === req.params.id);
  if (!row) return fail(res, 404, "not_found", "ingest not found");
  if (row.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your ingest");
  }
  const scanId = String(req.body?.scanId || row.scanId || "");
  if (!scanId) return fail(res, 400, "bad_request", "scanId required");

  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const signals = row.signals.map((s) => ({ type: s.type, payload: s.payload }));
  try {
    const r = await fetch(`${DEEP_A_URL}/v1/scan/${scanId}/signals`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ signals }),
    });
    const j = await r.json();
    if (!r.ok) {
      return fail(res, r.status, j?.error?.code || "forward_failed", j?.error?.message || "forward failed");
    }
    row.status = "forwarded";
    row.forwardedAt = new Date().toISOString();
    row.scanId = scanId;
    save(INGEST, db);
    return ok(res, { forwarded: true, scan: j.data, ingestId: row.id });
  } catch (e) {
    return fail(res, 502, "deep_a_unreachable", e.message || "deep-a unreachable");
  }
});

app.get("/v1/ingest/mine", auth, (req, res) => {
  const db = load(INGEST, { items: [] });
  const list = db.items
    .filter((x) => x.userId === req.user.sub || req.user.role === "admin")
    .slice(0, 50)
    .map((x) => ({
      id: x.id,
      status: x.status,
      scanId: x.scanId,
      signalCount: x.signals?.length || 0,
      riskSum: x.riskSum,
      tags: x.tags,
      createdAt: x.createdAt,
    }));
  return ok(res, { items: list });
});

app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 ${SERVICE} Phase 5 on :${PORT}`);
});