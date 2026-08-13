/**
 * Phase 11 — div-auth
 * Register / login / OTP / JWT session skeleton
 * Passive scan only control plane — no game interference
 */
import express from "express";
import cors from "cors";
import { createHash, randomBytes, scryptSync, timingSafeEqual, createHmac } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { verifyServiceRequest } from "./serviceAuth.js";
import { rateLimit, securityHeaders, applySecurity, pathFirewall } from "./hardening.js";
import { putJsonFile, getJsonFile, githubDbEnabled, hydrateLocalJson } from "./githubDb.js";
import { sendOtpEmail, sendHtmlEmail, mailConfigured } from "./mail.js";
import * as Owners from "./owners.js";

const app = express();
app.set("trust proxy", 1);
applySecurity(app);
app.use(cors({ origin: true }));
app.use(express.static("public"));
app.use(express.json({
  limit: "256kb",
  verify: (req, _res, buf) => { req.rawBody = buf.toString("utf8"); },
}));


const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-div-auth";
const SERVICE_SECRET = process.env.SERVICE_SECRET || JWT_SECRET;
const ALLOWED_SERVICES = (process.env.ALLOWED_SERVICES || "div-user-link,div-scan-deep-a,div-scan-deep-b,div-scan-dark-a,div-scan-dark-b,div-ai-light,div-ai-heavy")
  .split(",").map((s) => s.trim()).filter(Boolean);

function serviceAuth(req, res, next) {
  const r = verifyServiceRequest(req, { serviceSecret: SERVICE_SECRET, allowedServices: ALLOWED_SERVICES });
  if (!r.ok) return fail(res, 401, r.code || "service_unauthorized", "service auth failed");
  req.serviceName = r.serviceName;
  next();
}

const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });
const USERS = join(DATA, "users.json");
const OTPS = join(DATA, "otps.json");
const SESSIONS = join(DATA, "sessions.json");

const AUDIT = join(DATA, "audit.json");
function auditLog(entry) {
  try {
    const db = load(AUDIT, { items: [] });
    db.items.unshift({
      id: randomBytes(6).toString("hex"),
      at: new Date().toISOString(),
      ...entry,
    });
    db.items = db.items.slice(0, 500);
    save(AUDIT, db);
    if (githubDbEnabled()) {
      putJsonFile("audit/audit.json", db, "audit sync").catch(() => {});
    }
  } catch (e) {
    console.error("audit", e.message);
  }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return fail(res, 403, "forbidden", `requires role: ${roles.join("|")}`);
    }
    next();
  };
}

// ensure load/save exist before ensureAdmin - moved call to listen


const SERVICE = "div-auth";



function load(file, fallback) {
  if (!existsSync(file)) return fallback;
  try { return JSON.parse(readFileSync(file, "utf8")); } catch { return fallback; }
}
function save(file, data) {
  writeFileSync(file, JSON.stringify(data, null, 2));
}
const GH_PATHS = {
  USERS: "users/users.json",
  SESSIONS: "sessions/sessions.json",
  OTPS: "otp/otps.json",
};
function saveAndSync(file, data, key) {
  save(file, data);
  const rel = GH_PATHS[key];
  if (rel && githubDbEnabled()) {
    putJsonFile(rel, data, `sync ${rel}`).catch((e) => console.error("gh sync", rel, e.message));
  }
}
function ensureAdminExists() {
  const db = load(USERS, { users: [] });
  if (!db.users.length) return;
  const boot = (process.env.ADMIN_BOOTSTRAP_EMAIL || "").toLowerCase().trim();
  if (boot) {
    const u = db.users.find((x) => x.email === boot);
    if (u && u.role !== "admin") {
      u.role = "admin";
      saveAndSync(USERS, db, "USERS");
      console.log("Bootstrap admin", boot);
      return;
    }
  }
  if (db.users.some((u) => u.role === "admin")) return;
  db.users[0].role = "admin";
  saveAndSync(USERS, db, "USERS");
  console.log("Promoted first user to admin", db.users[0].email);
}



function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const hash = scryptSync(password, salt, 32).toString("hex");
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const h = scryptSync(password, salt, 32);
  const expected = Buffer.from(hash, "hex");
  return h.length === expected.length && timingSafeEqual(h, expected);
}

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}
function signJwt(payload, ttlSec = 900) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + ttlSec,
  }));
  const sig = createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
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

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    emailVerified: !!u.emailVerified,
    createdAt: u.createdAt,
  };
}

function ok(res, data, status = 200) {
  return res.status(status).json({ ok: true, data, version: "v1", service: SERVICE });
}
function fail(res, status, code, message) {
  return res.status(status).json({ ok: false, error: { code, message }, service: SERVICE });
}

app.get("/admin", (_req, res) => res.redirect("/admin.html"));

app.get("/ready", (_req, res) => {
  res.json({ ready: true, service: typeof SERVICE !== "undefined" ? SERVICE : "ok" });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: SERVICE, phase: 11, time: new Date().toISOString(), uptimeSec: Math.floor(process.uptime()) });
});
app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    phase: 11,
    group: "A — Security",
    endpoints: [
      "POST /v1/auth/register",
      "POST /v1/auth/login",
      "POST /v1/auth/otp/verify",
      "POST /v1/auth/otp/resend",
      "POST /v1/auth/refresh",
      "GET /v1/auth/me",
      "POST /v1/device/bind",
    ],
    policy: "Passive integrity control plane only — does not modify games",
  });
});

const authLimit = rateLimit({ windowMs: 60_000, max: 20, keyFn: (r) => "auth:" + (r.ip || "") });
const joinLimit = rateLimit({ windowMs: 60_000, max: 10, keyFn: (r) => "join:" + (r.ip || "") });
const adminLimit = rateLimit({ windowMs: 60_000, max: 60, keyFn: (r) => "admin:" + (r.ip || "") });
app.post("/v1/auth/register", authLimit, async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const role = req.body?.role === "owner" ? "owner" : "user";
  if (!username || username.length < 3) return fail(res, 400, "bad_username", "username min 3 chars");
  if (!email.includes("@")) return fail(res, 400, "bad_email", "valid email required");
  if (password.length < 8) return fail(res, 400, "bad_password", "password min 8 chars");

  const db = load(USERS, { users: [] });
  if (db.users.some((u) => u.email === email)) return fail(res, 409, "email_exists", "email already registered");
  if (db.users.some((u) => u.username === username)) return fail(res, 409, "username_exists", "username taken");

  const { salt, hash } = hashPassword(password);
  const user = {
    id: randomBytes(8).toString("hex"),
    username,
    email,
    passwordSalt: salt,
    passwordHash: hash,
    role: (db.users.length === 0 || !db.users.some((x) => x.role === "admin")) ? "admin" : (role || "user"),
    emailVerified: false,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  saveAndSync(USERS, db, "USERS");

  // OTP
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const otps = load(OTPS, { items: [] });
  otps.items = otps.items.filter((o) => o.email !== email);
  otps.items.push({
    email,
    codeHash: createHash("sha256").update(code).digest("hex"),
    expiresAt: Date.now() + 10 * 60 * 1000,
    attempts: 0,
  });
  saveAndSync(OTPS, otps, "OTPS");

  const token = signJwt({ sub: user.id, role: user.role, email: user.email }, 900);
  const refresh = randomBytes(24).toString("hex");
  const sessions = load(SESSIONS, { items: [] });
  sessions.items.push({
    id: randomBytes(8).toString("hex"),
    userId: user.id,
    refreshHash: createHash("sha256").update(refresh).digest("hex"),
    expiresAt: Date.now() + 7 * 24 * 3600 * 1000,
  });
  saveAndSync(SESSIONS, sessions, "SESSIONS");

  let mailResult;
  try { mailResult = await sendOtpEmail(email, code); }
  catch (e) { mailResult = { ok: false, mode: "error", error: e.message, devCode: mailConfigured() ? undefined : code }; }
  return ok(res, {
    user: publicUser(user),
    token,
    refreshToken: refresh,
    otp: {
      sent: !!mailResult?.ok,
      mode: mailResult?.mode || "log",
      devCode: mailResult?.mode === "log" || mailResult?.mode === "error" ? code : undefined,
    },
    message: "Registered. Verify OTP.",
  }, 201);
});

app.post("/v1/auth/login", authLimit, (req, res) => {
  const login = String(req.body?.login || req.body?.email || req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const db = load(USERS, { users: [] });
  const user = db.users.find((u) => u.email === login || u.username === login);
  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    return fail(res, 401, "invalid_credentials", "invalid login or password");
  }
  user.lastLoginAt = new Date().toISOString();
  saveAndSync(USERS, db, "USERS");
  const token = signJwt({ sub: user.id, role: user.role, email: user.email }, 900);
  const refresh = randomBytes(24).toString("hex");
  const sessions = load(SESSIONS, { items: [] });
  sessions.items.push({
    id: randomBytes(8).toString("hex"),
    userId: user.id,
    refreshHash: createHash("sha256").update(refresh).digest("hex"),
    expiresAt: Date.now() + 7 * 24 * 3600 * 1000,
  });
  saveAndSync(SESSIONS, sessions, "SESSIONS");
  return ok(res, { user: publicUser(user), token, refreshToken: refresh, tokenType: "Bearer" });
});

app.post("/v1/auth/otp/verify", authLimit, (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const code = String(req.body?.code || "").trim();
  const otps = load(OTPS, { items: [] });
  const row = otps.items.find((o) => o.email === email);
  if (!row) return fail(res, 400, "no_otp", "no otp pending");
  if (Date.now() > row.expiresAt) return fail(res, 400, "otp_expired", "otp expired");
  if (row.attempts >= 5) return fail(res, 429, "otp_locked", "too many attempts");
  row.attempts += 1;
  const hash = createHash("sha256").update(code).digest("hex");
  if (hash !== row.codeHash) {
    saveAndSync(OTPS, otps, "OTPS");
    return fail(res, 400, "otp_invalid", "invalid code");
  }
  otps.items = otps.items.filter((o) => o.email !== email);
  saveAndSync(OTPS, otps, "OTPS");
  const db = load(USERS, { users: [] });
  const user = db.users.find((u) => u.email === email);
  if (!user) return fail(res, 404, "user_not_found", "user not found");
  user.emailVerified = true;
  saveAndSync(USERS, db, "USERS");
  return ok(res, { user: publicUser(user), verified: true });
});

app.post("/v1/auth/otp/resend", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const db = load(USERS, { users: [] });
  if (!db.users.some((u) => u.email === email)) return fail(res, 404, "user_not_found", "user not found");
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const otps = load(OTPS, { items: [] });
  otps.items = otps.items.filter((o) => o.email !== email);
  otps.items.push({
    email,
    codeHash: createHash("sha256").update(code).digest("hex"),
    expiresAt: Date.now() + 10 * 60 * 1000,
    attempts: 0,
  });
  saveAndSync(OTPS, otps, "OTPS");
  let mailResult;
  try { mailResult = await sendOtpEmail(email, code); }
  catch (e) { mailResult = { ok: false, mode: "error", error: e.message, devCode: code }; }
  return ok(res, {
    sent: !!mailResult?.ok,
    mode: mailResult?.mode || "log",
    devCode: mailResult?.mode !== "smtp" ? code : undefined,
  });
});

app.post("/v1/auth/refresh", (req, res) => {
  const refreshToken = String(req.body?.refreshToken || "");
  const hash = createHash("sha256").update(refreshToken).digest("hex");
  const sessions = load(SESSIONS, { items: [] });
  const s = sessions.items.find((x) => x.refreshHash === hash && !x.revoked && x.expiresAt > Date.now());
  if (!s) return fail(res, 401, "invalid_refresh", "invalid refresh token");
  const db = load(USERS, { users: [] });
  const user = db.users.find((u) => u.id === s.userId);
  if (!user) return fail(res, 401, "invalid_refresh", "user missing");
  const token = signJwt({ sub: user.id, role: user.role, email: user.email }, 900);
  return ok(res, { token, tokenType: "Bearer", user: publicUser(user) });
});

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  const payload = verifyJwt(token);
  if (!payload) return fail(res, 401, "unauthorized", "valid token required");
  req.user = payload;
  next();
}

app.get("/v1/auth/me", authMiddleware, (req, res) => {
  const db = load(USERS, { users: [] });
  const user = db.users.find((u) => u.id === req.user.sub);
  if (!user) return fail(res, 404, "user_not_found", "user not found");
  return ok(res, { user: publicUser(user) });
});

// Phase 11 skeleton — full Play Integrity in later phase
app.post("/v1/device/bind", authMiddleware, (req, res) => {
  const installationId = String(req.body?.installationId || "");
  const androidIdHash = String(req.body?.androidIdHash || "");
  if (!installationId) return fail(res, 400, "bad_request", "installationId required");
  return ok(res, {
    bound: true,
    userId: req.user.sub,
    installationId,
    androidIdHash: androidIdHash || null,
    note: "Skeleton bind — Play Integrity verification in Phase 2+",
  });
});

// Phase 3 — internal service routes
app.get("/v1/internal/user/:id", serviceAuth, (req, res) => {
  const db = load(USERS, { users: [] });
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return fail(res, 404, "user_not_found", "user not found");
  return ok(res, { user: publicUser(user) });
});

app.get("/v1/internal/user-by-email/:email", serviceAuth, (req, res) => {
  const email = String(req.params.email || "").toLowerCase();
  const db = load(USERS, { users: [] });
  const user = db.users.find((u) => u.email === email);
  if (!user) return fail(res, 404, "user_not_found", "user not found");
  return ok(res, { user: publicUser(user) });
});

app.get("/v1/internal/verify-token", serviceAuth, (req, res) => {
  const token = String(req.query.token || req.body?.token || "");
  const payload = verifyJwt(token);
  if (!payload) return fail(res, 401, "invalid_token", "token invalid");
  return ok(res, { payload });
});


function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") return fail(res, 403, "forbidden", "admin only");
  next();
}

app.get("/v1/admin/users", authMiddleware, requireAdmin, (req, res) => {
  const db = load(USERS, { users: [] });
  const includeAdmin = String(req.query.includeAdmin || "") === "1";
  const users = db.users
    .filter((u) => includeAdmin || u.role !== "admin")
    .map((u) => ({
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      emailVerified: !!u.emailVerified,
      createdAt: u.createdAt,
    }));
  return ok(res, { users });
});

app.post("/v1/admin/users/:id/role", authMiddleware, requireAdmin, (req, res) => {
  const role = String(req.body?.role || "");
  if (!["admin", "owner", "user"].includes(role)) return fail(res, 400, "bad_role", "role must be admin|owner|user");
  const db = load(USERS, { users: [] });
  const u = db.users.find((x) => x.id === req.params.id);
  if (!u) return fail(res, 404, "not_found", "user not found");
  u.role = role;
  saveAndSync(USERS, db, "USERS");
  return ok(res, { user: publicUser(u) });
});

app.get("/v1/admin/stats", authMiddleware, requireAdmin, (req, res) => {
  const db = load(USERS, { users: [] });
  const roles = { admin: 0, owner: 0, user: 0 };
  for (const u of db.users) roles[u.role] = (roles[u.role] || 0) + 1;
  const sessions = load(SESSIONS, { items: [] });
  const owners = Owners.listOwners();
  return ok(res, {
    users: db.users.filter((u) => u.role !== "admin").length,
    roles,
    sessions: (sessions.items || sessions.sessions || []).length || 0,
    ownerRegistry: {
      total: owners.length,
      pending: owners.filter((o) => o.status === "pending").length,
      approved: owners.filter((o) => o.status === "approved").length,
      removed: owners.filter((o) => o.status === "removed").length,
      players: owners.reduce((n, o) => n + ((o.users || []).length), 0),
    },
  });
});



// ========== OWNER / ADMIN APP FLOW ==========
/** Owner APK: register only (no forgot). status=pending until admin approves */
app.post("/v1/owner/register", authLimit, async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!username || username.length < 3) return fail(res, 400, "bad_username", "username min 3 chars");
  if (!email.includes("@")) return fail(res, 400, "bad_email", "valid email required");
  if (password.length < 8) return fail(res, 400, "weak_password", "password min 8 chars");
  const { salt, hash } = hashPassword(password);
  const result = Owners.createOwnerRequest({ username, email, passwordHash: hash, salt });
  if (result.error === "email_exists") return fail(res, 409, "email_exists", "email already registered");
  if (result.error === "username_exists") return fail(res, 409, "username_exists", "username taken");
  return ok(res, {
    owner: result.owner,
    screen: "wait_for_admin_approval",
    message: "Wait for admin approval",
  }, 201);
});

/** Owner opens app again: check status (no classic login loop) */
app.post("/v1/owner/status", authLimit, async (req, res) => {
  // status recover from GitHub if local empty
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!email || !password) return fail(res, 400, "bad_request", "email and password required");
  let o = Owners.getOwnerByEmail(email);
  if (!o && Owners.pullFromGithub) {
    try { await Owners.pullFromGithub(); o = Owners.getOwnerByEmail(email); } catch (_) {}
  }
  if (!o) return fail(res, 404, "not_found", "owner not found — register first");
  // verify password against server hash (same account after reinstall)
  if (!verifyPassword(password, o.salt, o.passwordHash)) {
    return fail(res, 401, "invalid_credentials", "invalid email or password");
  }
  if (o.status === "pending") {
    return ok(res, { screen: "wait_for_admin_approval", owner: Owners.publicOwner(o) });
  }
  if (o.status === "removed") {
    return ok(res, { screen: "lock_panel", lockMessageHtml: o.lockMessageHtml, owner: Owners.publicOwner(o) });
  }
  // approved — issue JWT
  const token = signJwt({ sub: o.id, role: "owner", email: o.email, username: o.username }, 86400);
  return ok(res, {
    screen: "dashboard",
    token,
    owner: Owners.publicOwner(o, { includeReferral: true }),
    players: o.users || [],
    showReferralOnHome: !(o.users && o.users.length),
    showSettings: !!(o.users && o.users.length),
  });
});

app.get("/v1/owner/me", authMiddleware, (req, res) => {
  if (req.user.role !== "owner" && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "owner only");
  }
  const o = Owners.getOwnerById(req.user.sub);
  if (!o) return fail(res, 404, "not_found", "owner not found");
  if (o.status === "removed") {
    return ok(res, { screen: "lock_panel", lockMessageHtml: o.lockMessageHtml, owner: Owners.publicOwner(o) });
  }
  return ok(res, {
    screen: "dashboard",
    owner: Owners.publicOwner(o, { includeReferral: true }),
    players: o.users || [],
    showReferralOnHome: (o.users || []).length === 0,
    showSettings: (o.users || []).length > 0,
  });
});


/** Full server-side session snapshot — client must not trust local cache */
app.get("/v1/owner/session", authMiddleware, (req, res) => {
  if (req.user.role !== "owner" && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "owner only");
  }
  const o = Owners.getOwnerById(req.user.sub);
  if (!o) return fail(res, 404, "not_found", "owner not found on server");
  if (o.status === "removed") {
    return ok(res, {
      source: "server",
      screen: "lock_panel",
      lockMessageHtml: o.lockMessageHtml,
      owner: Owners.publicOwner(o),
      players: [],
    });
  }
  if (o.status !== "approved") {
    return ok(res, {
      source: "server",
      screen: "wait_for_admin_approval",
      owner: Owners.publicOwner(o),
      players: [],
    });
  }
  return ok(res, {
    source: "server",
    screen: "dashboard",
    owner: Owners.publicOwner(o, { includeReferral: true }),
    players: o.users || [],
    showReferralOnHome: !(o.users && o.users.length),
    showSettings: !!(o.users && o.users.length),
    serverTime: new Date().toISOString(),
  });
});

app.get("/v1/owner/referral", authMiddleware, (req, res) => {
  if (req.user.role !== "owner") return fail(res, 403, "forbidden", "owner only");
  const o = Owners.getOwnerById(req.user.sub);
  if (!o || o.status !== "approved") return fail(res, 403, "not_approved", "not approved");
  return ok(res, { referralCode: o.referralCode, username: o.username, email: o.email });
});

app.get("/v1/owner/players", authMiddleware, (req, res) => {
  if (req.user.role !== "owner") return fail(res, 403, "forbidden", "owner only");
  const players = Owners.listOwnerPlayers(req.user.sub) || [];
  return ok(res, { players });
});

/** Player (hidden notification app): join via referral + username */
app.post("/v1/player/join", joinLimit, (req, res) => {
  const username = String(req.body?.username || "").trim();
  const referralCode = String(req.body?.referralCode || "").trim();
  if (!username) return fail(res, 400, "username_required", "username required");
  if (!referralCode.startsWith("ds_ff/")) {
    return fail(res, 400, "invalid_code", "This code is incorrect");
  }
  const body = referralCode.slice("ds_ff/".length);
  if (body.length !== 24 || !/^[a-zA-Z0-9]+$/.test(body)) {
    return fail(res, 400, "invalid_code", "This code is incorrect");
  }
  const result = Owners.attachUserToOwner(referralCode, username);
  if (result.error === "invalid_code") return fail(res, 400, "invalid_code", "This code is incorrect");
  if (result.error) return fail(res, 400, result.error, result.error);
  // Player token — scan upload only (not admin/owner)
  const token = signJwt({
    sub: `player:${result.ownerId}:${result.username}`,
    role: "player",
    username: result.username,
    ownerId: result.ownerId,
    email: `${result.username}@player.div`,
    scope: ["scan:write", "player:session"],
  }, 86400 * 7);
  auditLog({
    action: "player.join",
    actor: result.username,
    ownerId: result.ownerId,
    meta: { alreadyJoined: !!result.alreadyJoined },
  });
  return ok(res, {
    screen: "you_are_approved",
    message: "You are approved",
    ownerUsername: result.ownerUsername,
    username: result.username,
    ownerId: result.ownerId,
    token,
    alreadyJoined: !!result.alreadyJoined,
  });
});

// ---- Admin owner management ----
app.get("/v1/admin/audit", authMiddleware, requireAdmin, adminLimit, (req, res) => {
  const db = load(AUDIT, { items: [] });
  return ok(res, { items: (db.items || []).slice(0, 100) });
});

app.get("/v1/admin/owners", authMiddleware, requireAdmin, (req, res) => {
  const list = Owners.listOwners().map((o) => Owners.publicOwner(o, { includeReferral: true }));
  return ok(res, { owners: list });
});

app.get("/v1/admin/owners/pending", authMiddleware, requireAdmin, (req, res) => {
  const list = Owners.listOwners()
    .filter((o) => o.status === "pending")
    .map((o) => Owners.publicOwner(o));
  return ok(res, { owners: list });
});

app.post("/v1/admin/owners/:id/approve", authMiddleware, requireAdmin, async (req, res) => {
  const result = Owners.approveOwner(req.params.id);
  if (result.error) return fail(res, 404, "not_found", "owner not found");
  const o = Owners.getOwnerById(req.params.id);
  // Phase 12 — HTML email via div-mail gateway / SMTP
  if (o?.email) {
    const html = `<div style="font-family:system-ui,sans-serif;max-width:520px;background:#0b1020;color:#e8eef9;padding:24px;border-radius:12px">
      <h2 style="color:#34d399;margin:0 0 12px">Approval successful</h2>
      <p>Hi <strong>${o.username || "owner"}</strong>,</p>
      <p>Admin approved your <strong>Div Owner</strong> account.</p>
      <p>Open the Owner app to see your <strong>dashboard</strong> and <strong>referral code</strong>.</p>
      <p style="color:#8b9bb4;font-size:13px">If the app still shows waiting, tap <em>Check approval status</em>.</p>
    </div>`;
    try {
      await sendHtmlEmail(o.email, "Div Integrity — Owner approved", html, "Your owner account was approved. Open the app.");
    } catch (e) {
      console.error("approve mail", e.message);
    }
  }
  auditLog({ action: "owner.approve", actor: req.user.sub, ownerId: req.params.id, meta: { username: result.owner?.username } });
  return ok(res, { owner: result.owner, referralCode: result.referralCode });
});

app.post("/v1/admin/owners/:id/remove", authMiddleware, requireAdmin, async (req, res) => {
  const htmlMsg = String(req.body?.lockMessageHtml || req.body?.message || "<h2>Removed</h2><p>Contact admin</p>");
  const result = Owners.removeOwner(req.params.id, htmlMsg);
  if (result.error) return fail(res, 404, "not_found", "owner not found");
  const o = Owners.getOwnerById(req.params.id);
  // Phase 12 — lock panel HTML stored on owner + email notice
  if (o?.email) {
    const html = `<div style="font-family:system-ui,sans-serif;max-width:520px;background:#0b1020;color:#e8eef9;padding:24px;border-radius:12px">
      <h2 style="color:#f87171;margin:0 0 12px">You are removed</h2>
      <p>Please open the Owner app and read the admin message.</p>
      <div style="margin-top:16px;padding:14px;background:#121826;border-radius:10px;border:1px solid #2a3348">
        ${o.lockMessageHtml || htmlMsg}
      </div>
    </div>`;
    try {
      await sendHtmlEmail(o.email, "Div Integrity — Access removed", html, "You are removed. Open the app for admin message.");
    } catch (e) {
      console.error("remove mail", e.message);
    }
  }
  auditLog({ action: "owner.remove", actor: req.user.sub, ownerId: req.params.id });
  return ok(res, { owner: result.owner });
});

app.post("/v1/admin/owners/:id/reapprove", authMiddleware, requireAdmin, (req, res) => {
  const result = Owners.reapproveOwner(req.params.id);
  if (result.error) return fail(res, 404, "not_found", "owner not found");
  return ok(res, { owner: result.owner, referralCode: result.referralCode });
});

app.get("/v1/admin/owners/:id/players", authMiddleware, requireAdmin, (req, res) => {
  const players = Owners.listOwnerPlayers(req.params.id);
  if (players === null) return fail(res, 404, "not_found", "owner not found");
  const o = Owners.getOwnerById(req.params.id);
  return ok(res, { owner: Owners.publicOwner(o), players });
});



app.post("/v1/admin/test-email", authMiddleware, requireAdmin, async (req, res) => {
  const to = String(req.body?.to || "").trim().toLowerCase();
  if (!to.includes("@")) return fail(res, 400, "bad_email", "valid to required");
  const kind = String(req.body?.kind || "approval");
  let subject, html;
  if (kind === "remove") {
    subject = "Div Integrity — Access removed";
    html = `<div style="font-family:system-ui,sans-serif;max-width:520px">
      <h2 style="color:#b91c1c">You are removed</h2>
      <p>Please open the app and read the admin message.</p>
      <div style="padding:12px;border-radius:8px;background:#fef2f2;border:1px solid #fecaca">
        <h3 style="margin:0 0 8px">Lock Panel</h3>
        <p style="margin:0">Your owner access was removed by admin. Contact support if this is a mistake.</p>
      </div>
    </div>`;
  } else {
    subject = "Div Integrity — Owner approved";
    html = `<div style="font-family:system-ui,sans-serif;max-width:520px">
      <h2 style="color:#047857">Approval successful</h2>
      <p>Admin approved your owner account.</p>
      <p>Open the <b>Owner app</b> to see your dashboard and referral code.</p>
      <p style="color:#64748b;font-size:13px">This is a system email from Div Integrity.</p>
    </div>`;
  }
  try {
    const { sendHtmlEmail, mailConfigured } = await import("./mail.js");
    if (!mailConfigured()) {
      return ok(res, { sent: false, mode: "log", message: "SMTP not configured", preview: { to, subject } });
    }
    const r = await sendHtmlEmail(to, subject, html);
    return ok(res, { sent: !!r.ok, mode: r.mode, to, subject, error: r.error || null });
  } catch (e) {
    return fail(res, 500, "mail_error", e.message);
  }
});

app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));

// Boot hydrate durable DB from GitHub (survives Render free disk wipe)
async function bootHydrate() {
  try {
    const r1 = await hydrateLocalJson(USERS, "users/users.json", writeFileSync, existsSync, readFileSync);
    console.log("hydrate users", r1);
    if (Owners.pullFromGithub) {
      const r2 = await Owners.pullFromGithub();
      console.log("hydrate owners", r2);
    }
  } catch (e) {
    console.error("bootHydrate", e.message);
  }
  ensureAdminExists();
}
bootHydrate();

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 div-auth Phase 11 on :${PORT}`);
});