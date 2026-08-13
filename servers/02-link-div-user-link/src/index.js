/**
 * Phase 2 — div-user-link
 * Owner ↔ User linking + consent ledger
 * Calls div-auth for JWT validation (or shared JWT_SECRET local verify)
 */
import express from "express";
import cors from "cors";
import { createHmac, randomBytes, createHash } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { verifyServiceRequest, serviceFetch } from "./serviceAuth.js";
import { rateLimit, securityHeaders, applySecurity, pathFirewall } from "./hardening.js";
import { putJsonFile, getJsonFile, githubDbEnabled } from "./githubDb.js";

const app = express();
app.set("trust proxy", 1);
applySecurity(app);
app.use(cors({ origin: true }));
app.use(express.json({
  limit: "256kb",
  verify: (req, _res, buf) => { req.rawBody = buf.toString("utf8"); },
}));


const PORT = process.env.PORT || 3000;
const SERVICE = "div-user-link";
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-div-auth";
const SERVICE_SECRET = process.env.SERVICE_SECRET || JWT_SECRET;
const SERVICE_NAME = "div-user-link";

const AUTH_URL = (process.env.AUTH_URL || "https://div-auth.onrender.com").replace(/\/$/, "");
const DEEP_A_URL = (process.env.DEEP_A_URL || "https://div-scan-deep-a.onrender.com").replace(/\/$/, "");
const DEEP_B_URL = (process.env.DEEP_B_URL || "https://div-scan-deep-b.onrender.com").replace(/\/$/, "");
const DARK_A_URL = (process.env.DARK_A_URL || "https://div-scan-dark-a.onrender.com").replace(/\/$/, "");
const DARK_B_URL = (process.env.DARK_B_URL || "https://div-scan-dark-b.onrender.com").replace(/\/$/, "");
const AI_LIGHT_URL = (process.env.AI_LIGHT_URL || "https://div-ai-light.onrender.com").replace(/\/$/, "");
const AI_HEAVY_URL = (process.env.AI_HEAVY_URL || "https://div-ai-heavy.onrender.com").replace(/\/$/, "");
const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });

const LINKS = join(DATA, "links.json");
const CONSENTS = join(DATA, "consents.json");
const DEVICES = join(DATA, "devices.json");

function load(file, fb) {
  if (!existsSync(file)) return fb;
  try { return JSON.parse(readFileSync(file, "utf8")); } catch { return fb; }
}
function save(file, data) { writeFileSync(file, JSON.stringify(data, null, 2)); }
const GH_PATHS = {"LINKS": "links/links.json", "CONSENTS": "consents/consents.json", "DEVICES": "devices/devices.json"};
function saveAndSync(file, data, key) {
  save(file, data);
  const rel = GH_PATHS[key];
  if (rel && githubDbEnabled()) {
    putJsonFile(rel, data, `sync ${rel}`).catch((e) => console.error("gh sync", rel, e.message));
  }
}


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

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return fail(res, 403, "forbidden", `requires role: ${roles.join("|")}`);
    }
    next();
  };
}

app.get("/ready", (_req, res) => {
  res.json({ ready: true, service: typeof SERVICE !== "undefined" ? SERVICE : "ok" });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: SERVICE,
    phase: 10,
    authUrl: AUTH_URL || null,
    time: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
  });
});

app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    phase: 10,
    group: "A — User linking + consent",
    endpoints: [
      "POST /v1/link/request",
      "POST /v1/link/accept",
      "POST /v1/link/revoke",
      "GET  /v1/link/mine",
      "GET  /v1/link/owner/users",
      "POST /v1/consent",
      "GET  /v1/consent/mine",
      "POST /v1/device/register",
      "GET  /v1/device/mine",
      "GET  /v1/agg/health-all",
      "GET  /v1/agg/owner-summary",
      "GET  /v1/agg/user/:userId",
      "GET  /v1/agg/report/:kind/:id",
    ],
    policy: "Consent required before any scan orchestration",
  });
});

/** Owner creates invite code for a user email */
app.post("/v1/link/request", auth, requireRole("owner", "admin"), (req, res) => {
  const userEmail = String(req.body?.userEmail || "").trim().toLowerCase();
  if (!userEmail.includes("@")) return fail(res, 400, "bad_email", "userEmail required");
  const code = randomBytes(4).toString("hex");
  const db = load(LINKS, { items: [] });
  db.items.push({
    id: randomBytes(8).toString("hex"),
    ownerId: req.user.sub,
    ownerEmail: req.user.email,
    userEmail,
    userId: null,
    code,
    status: "pending",
    createdAt: new Date().toISOString(),
  });
  saveAndSync(LINKS, db, "LINKS");
  return ok(res, { inviteCode: code, userEmail, status: "pending" }, 201);
});

/** User accepts invite with code */
app.post("/v1/link/accept", auth, (req, res) => {
  const code = String(req.body?.code || "").trim();
  if (!code) return fail(res, 400, "bad_code", "code required");
  const db = load(LINKS, { items: [] });
  const row = db.items.find((x) => x.code === code && x.status === "pending");
  if (!row) return fail(res, 404, "not_found", "invite not found");
  if (row.userEmail && row.userEmail !== req.user.email) {
    return fail(res, 403, "email_mismatch", "invite email does not match");
  }
  row.userId = req.user.sub;
  row.userEmail = req.user.email;
  row.status = "active";
  row.acceptedAt = new Date().toISOString();
  saveAndSync(LINKS, db, "LINKS");
  return ok(res, { link: row });
});

app.post("/v1/link/revoke", auth, (req, res) => {
  const linkId = String(req.body?.linkId || "");
  const db = load(LINKS, { items: [] });
  const row = db.items.find((x) => x.id === linkId);
  if (!row) return fail(res, 404, "not_found", "link not found");
  const isOwner = row.ownerId === req.user.sub;
  const isUser = row.userId === req.user.sub;
  if (!isOwner && !isUser && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your link");
  }
  row.status = "revoked";
  row.revokedAt = new Date().toISOString();
  saveAndSync(LINKS, db, "LINKS");
  return ok(res, { link: row });
});

app.get("/v1/link/mine", auth, (req, res) => {
  const db = load(LINKS, { items: [] });
  const items = db.items.filter(
    (x) => x.ownerId === req.user.sub || x.userId === req.user.sub || x.userEmail === req.user.email
  );
  return ok(res, { links: items });
});

app.get("/v1/link/owner/users", auth, requireRole("owner", "admin"), (req, res) => {
  const db = load(LINKS, { items: [] });
  const items = db.items.filter((x) => x.ownerId === req.user.sub && x.status === "active");
  return ok(res, { users: items });
});

/** Explicit scan consent */
app.post("/v1/consent", auth, (req, res) => {
  const scope = String(req.body?.scope || "device_scan");
  const granted = req.body?.granted !== false;
  const version = String(req.body?.policyVersion || "2026-08-1");
  const db = load(CONSENTS, { items: [] });
  db.items.push({
    id: randomBytes(8).toString("hex"),
    userId: req.user.sub,
    email: req.user.email,
    scope,
    granted,
    policyVersion: version,
    createdAt: new Date().toISOString(),
  });
  saveAndSync(CONSENTS, db, "CONSENTS");
  return ok(res, { consent: db.items[db.items.length - 1] }, 201);
});

app.get("/v1/consent/mine", auth, (req, res) => {
  const db = load(CONSENTS, { items: [] });
  const items = db.items.filter((x) => x.userId === req.user.sub);
  const latest = {};
  for (const c of items) latest[c.scope] = c;
  return ok(res, { consents: items, latestByScope: latest });
});

/** Register device under user (no scan yet) */
app.post("/v1/device/register", auth, (req, res) => {
  const installationId = String(req.body?.installationId || "");
  const label = String(req.body?.label || "device");
  const platform = String(req.body?.platform || "android");
  if (!installationId) return fail(res, 400, "bad_request", "installationId required");
  const db = load(DEVICES, { items: [] });
  let row = db.items.find((x) => x.userId === req.user.sub && x.installationId === installationId);
  if (!row) {
    row = {
      id: randomBytes(8).toString("hex"),
      userId: req.user.sub,
      installationId,
      label,
      platform,
      createdAt: new Date().toISOString(),
    };
    db.items.push(row);
  } else {
    row.label = label;
    row.updatedAt = new Date().toISOString();
  }
  saveAndSync(DEVICES, db, "DEVICES");
  return ok(res, { device: row }, 201);
});

app.get("/v1/device/mine", auth, (req, res) => {
  const db = load(DEVICES, { items: [] });
  return ok(res, { devices: db.items.filter((x) => x.userId === req.user.sub) });
});

/** Internal: can owner scan this user? */
app.get("/v1/policy/can-scan", auth, requireRole("owner", "admin"), (req, res) => {
  const userId = String(req.query.userId || "");
  const links = load(LINKS, { items: [] }).items;
  const linked = links.find(
    (x) => x.ownerId === req.user.sub && x.userId === userId && x.status === "active"
  );
  if (!linked && req.user.role !== "admin") {
    return ok(res, { allowed: false, reason: "not_linked" });
  }
  const consents = load(CONSENTS, { items: [] }).items.filter((c) => c.userId === userId);
  const scanConsent = [...consents].reverse().find((c) => c.scope === "device_scan");
  if (!scanConsent || !scanConsent.granted) {
    return ok(res, { allowed: false, reason: "no_consent" });
  }
  return ok(res, { allowed: true, linkId: linked?.id, consentId: scanConsent.id });
});


/** Phase 10 — Aggregator */
async function fetchBearer(url, token) {
  try {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const j = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data: j?.data ?? j };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  }
}

app.get("/v1/agg/health-all", auth, requireRole("owner", "admin"), async (req, res) => {
  const urls = {
    auth: AUTH_URL + "/health",
    link: "/health",
    deepA: DEEP_A_URL + "/health",
    deepB: DEEP_B_URL + "/health",
    darkA: DARK_A_URL + "/health",
    darkB: DARK_B_URL + "/health",
    aiLight: AI_LIGHT_URL + "/health",
    aiHeavy: AI_HEAVY_URL + "/health",
  };
  const out = {};
  // local
  out.link = { ok: true, service: SERVICE, phase: 10 };
  await Promise.all(
    Object.entries(urls)
      .filter(([k]) => k !== "link")
      .map(async ([k, u]) => {
        try {
          const r = await fetch(u);
          out[k] = await r.json();
        } catch (e) {
          out[k] = { ok: false, error: e.message };
        }
      })
  );
  return ok(res, { services: out });
});

app.get("/v1/agg/owner-summary", auth, requireRole("owner", "admin"), async (req, res) => {
  const token = (req.headers.authorization || "").replace(/^Bearer\\s+/i, "");
  const links = load(LINKS, { items: [] }).items.filter(
    (x) => x.ownerId === req.user.sub && x.status === "active"
  );
  const [deep, dark, triage, jobs] = await Promise.all([
    fetchBearer(DEEP_A_URL + "/v1/scans/mine", token),
    fetchBearer(DARK_A_URL + "/v1/observe/mine", token),
    fetchBearer(AI_LIGHT_URL + "/v1/triage/mine", token),
    fetchBearer(AI_HEAVY_URL + "/v1/jobs/mine", token),
  ]);
  return ok(res, {
    linkedUsers: links.length,
    links: links.map((l) => ({
      id: l.id,
      userId: l.userId,
      userEmail: l.userEmail,
      status: l.status,
    })),
    deepScans: deep.ok ? deep.data?.scans || deep.data : [],
    darkObserves: dark.ok ? dark.data?.items || dark.data : [],
    triages: triage.ok ? triage.data?.items || triage.data : [],
    heavyJobs: jobs.ok ? jobs.data?.jobs || jobs.data : [],
    upstream: {
      deep: deep.ok,
      dark: dark.ok,
      triage: triage.ok,
      jobs: jobs.ok,
    },
  });
});

app.get("/v1/agg/user/:userId", auth, requireRole("owner", "admin"), async (req, res) => {
  const userId = String(req.params.userId);
  const links = load(LINKS, { items: [] }).items;
  const linked = links.find(
    (x) => x.ownerId === req.user.sub && x.userId === userId && x.status === "active"
  );
  if (!linked && req.user.role !== "admin") {
    return fail(res, 403, "not_linked", "user not linked to you");
  }
  const consents = load(CONSENTS, { items: [] }).items.filter((c) => c.userId === userId);
  const devices = load(DEVICES, { items: [] }).items.filter((d) => d.userId === userId);
  const token = (req.headers.authorization || "").replace(/^Bearer\\s+/i, "");
  const [deep, dark] = await Promise.all([
    fetchBearer(DEEP_A_URL + "/v1/scans/mine", token),
    fetchBearer(DARK_A_URL + "/v1/observe/mine", token),
  ]);
  const scans = (deep.data?.scans || []).filter(
    (s) => s.targetUserId === userId || s.requestedBy === req.user.sub
  );
  const observes = (dark.data?.items || []).filter(
    (s) => s.targetUserId === userId || true
  );
  return ok(res, {
    userId,
    link: linked || null,
    consents,
    devices,
    scans,
    observes,
  });
});

app.get("/v1/agg/report/:kind/:id", auth, async (req, res) => {
  const kind = String(req.params.kind);
  const id = String(req.params.id);
  const token = (req.headers.authorization || "").replace(/^Bearer\\s+/i, "");
  const map = {
    deep: `${DEEP_A_URL}/v1/scan/${id}`,
    dark: `${DARK_A_URL}/v1/observe/${id}`,
    triage: `${AI_LIGHT_URL}/v1/triage/${id}`,
    job: `${AI_HEAVY_URL}/v1/jobs/${id}`,
    popup: `${DARK_B_URL}/v1/popup/${id}`,
    ingest: `${DEEP_B_URL}/v1/ingest/${id}`,
  };
  const url = map[kind];
  if (!url) return fail(res, 400, "bad_kind", "kind must be deep|dark|triage|job|popup|ingest");
  const r = await fetchBearer(url, token);
  if (!r.ok) return fail(res, r.status || 502, "upstream", r.error || "upstream failed");
  return ok(res, { kind, id, report: r.data });
});


app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 div-user-link Phase 2 on :${PORT}`);
});