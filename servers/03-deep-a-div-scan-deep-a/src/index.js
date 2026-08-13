/**
 * Phase 4 — div-scan-deep-a
 * Deep scan orchestration (FF off / manual full device)
 * Passive only — does not modify games or inject processes
 */
import express from "express";
import cors from "cors";
import { createHmac, randomBytes, createHash } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { verifyServiceRequest } from "./serviceAuth.js";
import { verifyPlayIntegrityToken, evaluateIntegrityPayload, playIntegrityConfigured } from "./playIntegrity.js";
import { rateLimit, securityHeaders, applySecurity, pathFirewall } from "./hardening.js";
import { putJsonFile, putTextFile, deleteFile, githubDbEnabled } from "./githubDb.js";

const app = express();
app.set("trust proxy", 1);
applySecurity(app);
app.use(cors({ origin: true }));
app.use(express.json({
  limit: "2mb",
  verify: (req, _res, buf) => { req.rawBody = buf.toString("utf8"); },
}));

const PORT = process.env.PORT || 3000;
const SERVICE = "div-scan-deep-a";
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-div-auth";
const SERVICE_SECRET = process.env.SERVICE_SECRET || JWT_SECRET;
const LINK_URL = (process.env.LINK_URL || "https://div-user-link.onrender.com").replace(/\/$/, "");
const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });
const SCANS = join(DATA, "scans.json");

function load(file, fb) {
  if (!existsSync(file)) return fb;
  try { return JSON.parse(readFileSync(file, "utf8")); } catch { return fb; }
}
function save(file, data) { writeFileSync(file, JSON.stringify(data, null, 2)); }
function saveScans(data) {
  save(SCANS, data);
  if (githubDbEnabled()) {
    putJsonFile("scans/deep-a.json", data, "sync deep-a scans").catch((e) => console.error("gh scans", e.message));
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
  if (!payload) return fail(res, 401, "unauthorized", "valid token required — no auth, no scan");
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

/** Optional: ask link service if owner can scan user */
async function canScan(ownerToken, userId) {
  try {
    const r = await fetch(`${LINK_URL}/v1/policy/can-scan?userId=${encodeURIComponent(userId)}`, {
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    const j = await r.json();
    return j?.data?.allowed === true;
  } catch {
    // If link service cold/unavailable, allow self-scan only (checked by caller)
    return null;
  }
}

app.get("/ready", (_req, res) => {
  res.json({ ready: true, service: typeof SERVICE !== "undefined" ? SERVICE : "ok" });
});

app.post("/v1/scan/:id/cleanup", auth, async (req, res) => {
  const id = req.params.id;
  const db = load(SCANS, { scans: [], results: [] });
  const scan = (db.scans || []).find((s) => s.id === id);
  if (scan && scan.ownerId && scan.ownerId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your scan");
  }
  const r = await cleanupScanArtifacts(id);
  return ok(res, r);
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: SERVICE,
    phase: 4,
    mode: "deep_v3_hard",
    time: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
  });
});

app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    phase: 4,
    group: "B — Deep Scan",
    policy: "Passive read-only. Does not cross or modify Free Fire / any game.",
    endpoints: [
      "POST /v1/scan/start",
      "GET  /v1/scan/:id",
      "GET  /v1/scan/:id/status",
      "POST /v1/scan/:id/signals",
      "POST /v1/scan/:id/complete",
      "GET  /v1/scans/mine",
    ],
  });
});

/**
 * Start deep scan
 * body: { targetUserId?, deviceId?, mode?: "deep", note? }
 * Owner scans linked user; user can scan self.
 */
app.post("/v1/scan/start", auth, async (req, res) => {
  // player or owner
  const targetUserId = String(req.body?.targetUserId || req.user.sub);
  const deviceId = String(req.body?.deviceId || "");
  const mode = "deep"; // this server is always deep
  const note = String(req.body?.note || "");

  // Authorization: self or owner/admin with link+consent
  if (targetUserId !== req.user.sub) {
    if (!["owner", "admin"].includes(req.user.role)) {
      return fail(res, 403, "forbidden", "only owner/admin can scan another user");
    }
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const allowed = await canScan(token, targetUserId);
    if (allowed === false) {
      return fail(res, 403, "not_allowed", "not linked or user has no device_scan consent");
    }
    // allowed === null → link service down; admin bypass, owner still blocked unless self
    if (allowed === null && req.user.role !== "admin") {
      return fail(res, 503, "link_unavailable", "link service unavailable; cannot verify consent");
    }
  }

  const db = load(SCANS, { scans: [] });
  const id = randomBytes(8).toString("hex");
  const scan = {
    id,
    mode,
    status: "running",
    intensity: "10000",
    requestedBy: req.user.sub,
    requestedByRole: req.user.role,
    targetUserId,
    deviceId: deviceId || null,
    note: note.slice(0, 200),
    signals: [],
    signalCount: 0,
    score: null,
    verdict: null,
    policy: {
      passiveOnly: true,
      noGameModify: true,
      noProcessInject: true,
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.scans.unshift(scan);
  // keep last 200
  db.scans = db.scans.slice(0, 200);
  saveScans(db);

  return ok(res, {
    scan: {
      id: scan.id,
      status: scan.status,
      mode: scan.mode,
      targetUserId: scan.targetUserId,
      createdAt: scan.createdAt,
      policy: scan.policy,
    },
  }, 201);
});

app.get("/v1/scan/:id", auth, (req, res) => {
  const db = load(SCANS, { scans: [] });
  const scan = db.scans.find((s) => s.id === req.params.id);
  if (!scan) return fail(res, 404, "not_found", "scan not found");
  if (
    scan.requestedBy !== req.user.sub &&
    scan.targetUserId !== req.user.sub &&
    req.user.role !== "admin"
  ) {
    return fail(res, 403, "forbidden", "not your scan");
  }
  return ok(res, { scan });
});

app.get("/v1/scan/:id/status", auth, (req, res) => {
  const db = load(SCANS, { scans: [] });
  const scan = db.scans.find((s) => s.id === req.params.id);
  if (!scan) return fail(res, 404, "not_found", "scan not found");
  if (
    scan.requestedBy !== req.user.sub &&
    scan.targetUserId !== req.user.sub &&
    req.user.role !== "admin"
  ) {
    return fail(res, 403, "forbidden", "not your scan");
  }
  return ok(res, {
    id: scan.id,
    status: scan.status,
    signalCount: scan.signalCount,
    score: scan.score,
    verdict: scan.verdict,
    updatedAt: scan.updatedAt,
  });
});

/**
 * Client / device agent uploads read-only signals
 * body: { signals: [{ type, payload }] }
 * types e.g. package_list, root_heuristic, overlay, integrity_token, accessibility_presence
 */
app.post("/v1/scan/:id/signals", auth, (req, res) => {
  const db = load(SCANS, { scans: [] });
  const idx = db.scans.findIndex((s) => s.id === req.params.id);
  if (idx < 0) return fail(res, 404, "not_found", "scan not found");
  const scan = db.scans[idx];
  if (scan.status !== "running" && scan.status !== "collecting") {
    return fail(res, 400, "closed", "scan not accepting signals");
  }
  if (
    scan.requestedBy !== req.user.sub &&
    scan.targetUserId !== req.user.sub &&
    req.user.role !== "admin"
  ) {
    return fail(res, 403, "forbidden", "not your scan");
  }

  const incoming = Array.isArray(req.body?.signals) ? req.body.signals : [];
  if (!incoming.length) return fail(res, 400, "bad_request", "signals array required");
  if (incoming.length > 300) return fail(res, 400, "too_many", "max 300 signals per batch");

  const blockedTypes = ["process_inject", "memory_write", "network_block", "game_hook"];
  for (const sig of incoming) {
    const type = String(sig?.type || "unknown").slice(0, 64);
    if (blockedTypes.includes(type)) {
      return fail(res, 400, "policy_violation", `signal type not allowed: ${type}`);
    }
    scan.signals.push({
      type,
      payload: sig.payload ?? {},
      at: new Date().toISOString(),
    });
  }
  // cap stored signals
  if (scan.signals.length > 2000) scan.signals = scan.signals.slice(-2000);
  scan.signalCount = scan.signals.length;
  scan.status = "collecting";
  scan.updatedAt = new Date().toISOString();
  db.scans[idx] = scan;
  saveScans(db);

  return ok(res, { id: scan.id, signalCount: scan.signalCount, status: scan.status });
});


/** Ultra deep passive signal analysis v3 (read-only scoring — no game touch) */

/** After AI finishes, purge scan payloads (keep DB light) — server + GitHub */
async function cleanupScanArtifacts(scanId) {
  const db = load(SCANS, { scans: [], results: [] });
  db.scans = (db.scans || []).filter((s) => s.id !== scanId);
  db.results = (db.results || []).filter((r) => r.scanId !== scanId);
  saveScans(db);
  if (githubDbEnabled()) {
    try {
      await deleteFile(`scans/active/${scanId}.json`, `cleanup scan ${scanId}`);
      await deleteFile(`scans/active/${scanId}.txt`, `cleanup scan txt ${scanId}`);
    } catch (e) {
      console.error("cleanup gh", e.message);
    }
  }
  return { ok: true, scanId };
}

function deepAnalyze(scan) {
  const signals = scan.signals || [];
  let score = 0;
  const findings = [];
  const categories = {
    root: 0, overlay: 0, accessibility: 0, packages: 0,
    integrity: 0, hooks: 0, network: 0, storage: 0, emulation: 0,
    debugger: 0, cert: 0, sandbox: 0, timing: 0,
  };

  // Expanded risk package regex bank (passive name match only)
  const RISK_PKG = [
    /xposed/i, /lsposed/i, /edxposed/i, /magisk/i, /supersu/i, /kingroot/i, /kingoroot/i,
    /frida/i, /substrate/i, /cydia/i, /gameguardian/i, /cheat.?engine/i, /mod.?menu/i,
    /lucky.?patcher/i, /freedom/i, /creehacks/i, /sb.?game/i, /parallel.?space/i,
    /virtual.?xposed/i, /taichi/i, /zygisk/i, /riru/i, /shadow.?app/i, /virtualapp/i,
    /vmos/i, /f1vm/i, /nox/i, /bluestacks/i, /ldplayer/i, /memu/i, /gameloop/i,
    /auto.?click/i, /autoclick/i, /clicker/i, /macro/i, /anmod/i, /apk.?editor/i,
    /mt.?manager/i, /np.?manager/i, /http.?canary/i, /packet.?capture/i, /reqable/i,
    /charles/i, /mitm/i, /ssl.?kill/i, /trustme.?already/i, /justtrustme/i,
    /hide.?my.?applist/i, /applist.?detector/i, /root.?cloak/i, /magisk.?hide/i,
    /shamiko/i, /lsposed/i, /edxposed/i, /bugjaeger/i, /termux/i,
  ];
  const RISK_KW = [
    "aimbot", "esp", "wallhack", "speedhack", "mod menu", "inject", "hook",
    "memory edit", "bypass", "anti ban", "auto headshot", "radar", "softaim",
    "force close", "dll inject", "opcode", "memory scan", "speed hack",
  ];

  const typeSet = new Set();
  let pkgCount = 0;
  let riskPkgHits = 0;

  for (const sig of signals) {
    const sigType = String(sig.type || "").toLowerCase();
    typeSet.add(sigType || "unknown");
    const payload = sig.payload || {};
    const text = JSON.stringify(payload).toLowerCase();

    // --- ROOT ---
    if (sigType.includes("root") || sigType === "root_heuristic" || sigType.includes("su")) {
      const flags = payload.flags || payload.indicators || payload.tags || [];
      const n = Array.isArray(flags) ? flags.length : (payload.suspect ? 2 : 1);
      const add = Math.min(30, 10 + n * 5);
      score += add; categories.root += add;
      findings.push({ cat: "root", detail: `root signals (+${add})`, weight: add });
    }
    if (/su\b|magisk|busybox|which su|\/system\/xbin\/su|\/system\/bin\/su|zygisk|kernelsu|apatch/.test(text)) {
      score += 15; categories.root += 15;
      findings.push({ cat: "root", detail: "su/magisk/kernelsu markers", weight: 15 });
    }
    if (/test-keys|userdebug|eng\.build/.test(text)) {
      score += 8; categories.root += 8;
      findings.push({ cat: "root", detail: "test-keys/userdebug build", weight: 8 });
    }

    // --- OVERLAY ---
    if (sigType.includes("overlay") || /system_alert_window|type_application_overlay|draw.?over/.test(text)) {
      score += 12; categories.overlay += 12;
      findings.push({ cat: "overlay", detail: "overlay / draw-over-apps", weight: 12 });
    }

    // --- ACCESSIBILITY ---
    if (sigType.includes("accessibility") || sigType === "accessibility_presence") {
      const services = payload.services || payload.enabled || payload.list || [];
      const count = Array.isArray(services) ? services.length : 1;
      const add = Math.min(28, 8 + count * 4);
      score += add; categories.accessibility += add;
      findings.push({ cat: "accessibility", detail: `accessibility services=${count}`, weight: add });
    }
    if (/autoclick|auto.?click|tap.?assistant|gesture.?service/.test(text)) {
      score += 18; categories.accessibility += 18;
      findings.push({ cat: "accessibility", detail: "auto-click / gesture service", weight: 18 });
    }

    // --- PACKAGES ---
    if (sigType.includes("package") || sigType === "package_list") {
      const pkgs = payload.packages || payload.list || payload.apps || [];
      const list = Array.isArray(pkgs) ? pkgs : [];
      pkgCount += list.length;
      for (const pkg of list) {
        const name = typeof pkg === "string" ? pkg : (pkg.packageName || pkg.name || "");
        for (const re of RISK_PKG) {
          if (re.test(name)) {
            riskPkgHits++;
            score += 16; categories.packages += 16;
            findings.push({ cat: "packages", detail: `risk package ${name}`, weight: 16 });
            break;
          }
        }
      }
      if (payload.flagged === true) {
        score += 10; categories.packages += 10;
        findings.push({ cat: "packages", detail: "client flagged package set", weight: 10 });
      }
    }

    // --- INTEGRITY ---
    if (sigType.includes("integrity") || sigType === "integrity_token" || sigType.includes("play_integrity")) {
      const verdict = String(payload.deviceIntegrity || payload.verdict || payload.appraisal || payload.meats || "").toLowerCase();
      if (verdict.includes("fail") || verdict.includes("unofficial") || verdict.includes("compromised") || payload.ok === false) {
        score += 25; categories.integrity += 25;
        findings.push({ cat: "integrity", detail: `integrity ${verdict || "fail"}`, weight: 25 });
      } else if (verdict.includes("meats_basic") || verdict.includes("basic")) {
        score += 8; categories.integrity += 8;
        findings.push({ cat: "integrity", detail: "basic integrity only", weight: 8 });
      }
    }

    // --- HOOKS / FRIDA ---
    if (sigType.includes("hook") || sigType.includes("frida") || sigType.includes("xposed") || /frida|xposed|substrate|gadget/.test(text)) {
      score += 24; categories.hooks += 24;
      findings.push({ cat: "hooks", detail: "hook/instrumentation markers", weight: 24 });
    }

    // --- EMULATOR ---
    if (sigType.includes("emulator") || sigType.includes("build") || /goldfish|ranchu|generic_x86|emulator|genymotion|vbox|nox|bluestacks|ldplayer/.test(text)) {
      const add = sigType.includes("emulator") ? 16 : 10;
      score += add; categories.emulation += add;
      findings.push({ cat: "emulation", detail: "emulator/cloud-device markers", weight: add });
    }
    if (/sdk_gphone|google_sdk|android.?sdk.?built.?for/.test(text)) {
      score += 12; categories.emulation += 12;
      findings.push({ cat: "emulation", detail: "SDK emulator fingerprint", weight: 12 });
    }

    // --- NETWORK / PROXY ---
    if (sigType.includes("network") || sigType.includes("proxy") || sigType.includes("vpn")) {
      if (payload.proxy || payload.vpn || /127\.0\.0\.1|localhost|:8080|:8888|:9050/.test(text)) {
        score += 10; categories.network += 10;
        findings.push({ cat: "network", detail: "proxy/vpn indicators", weight: 10 });
      }
    }

    // --- STORAGE / APK ---
    if (sigType.includes("storage") || sigType.includes("apk_path") || sigType.includes("file")) {
      if (/\/data\/local\/tmp|modmenu|\.xapk|split.?apk|obb.?mod/.test(text)) {
        score += 12; categories.storage += 12;
        findings.push({ cat: "storage", detail: "suspicious apk/storage paths", weight: 12 });
      }
    }

    // --- PERMISSIONS ---
    if (sigType.includes("permission") || sigType === "permissions") {
      const dangerous = [
        "WRITE_SECURE_SETTINGS", "BIND_ACCESSIBILITY_SERVICE",
        "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES", "DUMP", "PACKAGE_USAGE_STATS",
      ];
      const gtext = JSON.stringify(payload.granted || payload.list || []);
      for (const d of dangerous) {
        if (gtext.includes(d)) {
          score += 10; categories.accessibility += 10;
          findings.push({ cat: "permissions", detail: d, weight: 10 });
        }
      }
    }

    // --- INPUT INJECTION ---
    if (sigType.includes("sensor") || sigType.includes("input") || sigType.includes("touch")) {
      if (payload.inject || payload.autoClick || /inject|autoclick|touch.?sim|adb.?input/.test(text)) {
        score += 18; categories.hooks += 18;
        findings.push({ cat: "input", detail: "input injection markers", weight: 18 });
      }
    }

    // --- SANDBOX / CLONE ---
    if (/dual.?space|parallel.?space|clone|island|shelter|work.?profile|multiple.?app/.test(text)) {
      score += 12; categories.sandbox += 12;
      findings.push({ cat: "sandbox", detail: "clone / work-profile markers", weight: 12 });
    }

    // --- DEBUGGER ---
    if (sigType.includes("debug") || /debugger|tracerpid|wait.?for.?debugger/.test(text)) {
      score += 14; categories.debugger += 14;
      findings.push({ cat: "debugger", detail: "debugger / tracer markers", weight: 14 });
    }

    // --- CERT / SSL PIN BYPASS ---
    if (sigType.includes("cert") || sigType.includes("ssl") || /ssl.?unpin|trust.?all|user.?added.?ca/.test(text)) {
      score += 16; categories.cert += 16;
      findings.push({ cat: "cert", detail: "ssl/cert trust anomalies", weight: 16 });
    }

    // --- KEYWORDS ---
    for (const kw of RISK_KW) {
      if (text.includes(kw)) {
        score += 7; categories.packages += 7;
        findings.push({ cat: "keywords", detail: `keyword:${kw}`, weight: 7 });
      }
    }
  }

  // Meta correlation (hard mode)
  if (typeSet.size >= 4) {
    score += 6;
    findings.push({ cat: "meta", detail: `signal diversity ${typeSet.size}`, weight: 6 });
  }
  if (typeSet.size >= 8) {
    score += 8;
    findings.push({ cat: "meta", detail: `high diversity ${typeSet.size}`, weight: 8 });
  }
  const hot = Object.values(categories).filter((v) => v >= 15).length;
  if (hot >= 2) {
    score += 8;
    findings.push({ cat: "meta", detail: `risk clusters=${hot}`, weight: 8 });
  }
  if (hot >= 4) {
    score += 12;
    findings.push({ cat: "meta", detail: `multi-vector risk clusters=${hot}`, weight: 12 });
  }
  if (signals.length >= 15) {
    score += 5;
    findings.push({ cat: "meta", detail: `high signal volume ${signals.length}`, weight: 5 });
  }
  if (riskPkgHits >= 2) {
    score += 10;
    findings.push({ cat: "meta", detail: `multiple risk packages=${riskPkgHits}`, weight: 10 });
  }
  if (pkgCount === 0 && signals.length > 0) {
    score += 4;
    findings.push({ cat: "meta", detail: "no package list provided", weight: 4 });
  }
  // Empty scan still slightly elevated under hard mode (incomplete attestation)
  if (signals.length === 0) {
    score += 5;
    findings.push({ cat: "meta", detail: "empty signal set", weight: 5 });
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  let verdict = "clean_or_unclear";
  // Harder thresholds
  if (score >= 55) verdict = "likely_cheat_environment";
  else if (score >= 30) verdict = "suspicious";
  else if (score >= 12) verdict = "low_risk_signals";

  const seen = new Set();
  const uniq = [];
  for (const f of findings) {
    const k = f.cat + "|" + f.detail;
    if (seen.has(k)) continue;
    seen.add(k);
    uniq.push(f);
  }
  return {
    score,
    verdict,
    categories,
    findings: uniq.slice(0, 40),
    signalCount: signals.length,
    typeCount: typeSet.size,
    riskPkgHits,
    engine: "deep_v3_hard",
  };
}


/** Finalize deep scan with simple heuristic score (MVP) */
app.post("/v1/scan/:id/complete", auth, (req, res) => {
  const db = load(SCANS, { scans: [], results: [] });
  const scan = (db.scans || []).find((s) => s.id === req.params.id);
  if (!scan) return fail(res, 404, "not_found", "scan not found");
  if (scan.ownerId && scan.ownerId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your scan");
  }
  const analysis = deepAnalyze(scan);
  scan.status = "completed";
  scan.completedAt = new Date().toISOString();
  scan.score = analysis.score;
  scan.verdict = analysis.verdict;
  scan.analysis = analysis;
  // Auto text result for owner/AI (server-side only)
  const textLines = [
    `scanId=${scan.id}`,
    `score=${analysis.score}`,
    `verdict=${analysis.verdict}`,
    `engine=${analysis.engine}`,
    `signals=${analysis.signalCount}`,
    `types=${analysis.typeCount}`,
    `categories=${JSON.stringify(analysis.categories)}`,
    ...analysis.findings.map((f) => `[${f.cat}] +${f.weight} ${f.detail}`),
  ];
  const textContent = textLines.join("\n");
  db.results = db.results || [];
  db.results.unshift({
    id: randomBytes(8).toString("hex"),
    ownerId: scan.ownerId || req.user.sub,
    playerUsername: scan.targetUserId || scan.note || "device",
    label: `deep_scan_${scan.id}.txt`,
    textContent,
    bytes: Buffer.byteLength(textContent, "utf8"),
    createdAt: new Date().toISOString(),
    scanId: scan.id,
    score: analysis.score,
    verdict: analysis.verdict,
  });
  db.results = db.results.slice(0, 200);
  saveScans(db);
  return ok(res, { scan: { id: scan.id, status: scan.status, score: scan.score, verdict: scan.verdict, analysis }, resultTextBytes: Buffer.byteLength(textContent, "utf8") });
});

app.get("/v1/scans/mine", auth, (req, res) => {
  const db = load(SCANS, { scans: [] });
  const list = db.scans
    .filter((s) => s.requestedBy === req.user.sub || s.targetUserId === req.user.sub || req.user.role === "admin")
    .slice(0, 50)
    .map((s) => ({
      id: s.id,
      status: s.status,
      mode: s.mode,
      score: s.score,
      verdict: s.verdict,
      signalCount: s.signalCount,
      targetUserId: s.targetUserId,
      createdAt: s.createdAt,
    }));
  return ok(res, { scans: list });
});

app.post("/v1/integrity/verify", auth, async (req, res) => {
  const token = req.body?.integrityToken || req.body?.token || "";
  const payload = req.body?.payload || {};
  if (token) {
    const result = await verifyPlayIntegrityToken(token);
    return ok(res, { configured: playIntegrityConfigured(), result });
  }
  const evaluation = evaluateIntegrityPayload(payload);
  return ok(res, { configured: playIntegrityConfigured(), evaluation });
});

app.get("/v1/integrity/status", (_req, res) => {
  ok(res, { configured: playIntegrityConfigured(), mode: playIntegrityConfigured() ? "api" : "client_signal_only" });
});


/** Store scan artifact as TEXT only (zip/apk contents pre-converted by heavy pipeline) */
app.post("/v1/owner/results", auth, (req, res) => {
  if (req.user.role !== "owner" && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "owner only");
  }
  const playerUsername = String(req.body?.playerUsername || "").slice(0, 40);
  const text = String(req.body?.text || "");
  const label = String(req.body?.label || "scan.txt").slice(0, 80);
  if (!playerUsername) return fail(res, 400, "bad_request", "playerUsername required");
  if (!text) return fail(res, 400, "bad_request", "text required");
  if (text.length > 2_000_000) return fail(res, 400, "too_large", "max 2MB text");
  const db = load(SCANS, { scans: [], results: [] });
  db.results = db.results || [];
  const id = randomBytes(8).toString("hex");
  const row = {
    id,
    ownerId: req.user.sub,
    playerUsername,
    label: label.endsWith(".txt") ? label : label + ".txt",
    text,
    createdAt: new Date().toISOString(),
  };
  db.results.unshift(row);
  db.results = db.results.slice(0, 100);
  saveScans(db);
  return ok(res, { id: row.id, label: row.label, playerUsername, bytes: text.length }, 201);
});

app.get("/v1/owner/results", auth, (req, res) => {
  if (req.user.role !== "owner" && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "owner only");
  }
  const db = load(SCANS, { scans: [], results: [] });
  const player = req.query.player ? String(req.query.player) : null;
  let list = (db.results || []).filter((r) => r.ownerId === req.user.sub || req.user.role === "admin");
  if (player) list = list.filter((r) => r.playerUsername === player);
  return ok(res, {
    results: list.slice(0, 50).map((r) => ({
      id: r.id,
      playerUsername: r.playerUsername,
      label: r.label,
      bytes: (r.text || "").length,
      createdAt: r.createdAt,
    })),
  });
});

app.get("/v1/owner/results/:id", auth, (req, res) => {
  if (req.user.role !== "owner" && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "owner only");
  }
  const db = load(SCANS, { scans: [], results: [] });
  const r = (db.results || []).find((x) => x.id === req.params.id);
  if (!r) return fail(res, 404, "not_found", "result not found");
  if (r.ownerId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your result");
  }
  return ok(res, { result: r });
});


/** After AI finishes triage — purge scan payloads from server + GitHub (keep DB light). Owner meta stays. */
app.post("/v1/scan/:id/purge", auth, async (req, res) => {
  const db = load(SCANS, { scans: [], results: [] });
  const scan = (db.scans || []).find((s) => s.id === req.params.id);
  if (!scan) return fail(res, 404, "not_found", "scan not found");
  if (scan.ownerId && scan.ownerId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your scan");
  }
  // Keep only summary on result rows; strip heavy textContent/signals
  scan.signals = [];
  scan.purgedAt = new Date().toISOString();
  scan.status = scan.status === "completed" ? "completed_purged" : scan.status;
  for (const r of db.results || []) {
    if (r.scanId === scan.id) {
      r.textContent = r.textContent ? `[purged summary] score=${r.score} verdict=${r.verdict}` : "";
      r.purged = true;
    }
  }
  saveScans(db);
  // Delete heavy GitHub artifact if any
  try {
    if (githubDbEnabled()) {
      await deleteFile(`scans/artifacts/${scan.id}.txt`, `purge scan ${scan.id}`);
      await deleteFile(`scans/artifacts/${scan.id}.json`, `purge scan ${scan.id}`);
    }
  } catch (e) {
    console.error("purge gh", e.message);
  }
  return ok(res, { purged: true, scanId: scan.id });
});

/** Save intermediate artifact to GitHub during AI work */
app.post("/v1/scan/:id/artifact", auth, async (req, res) => {
  const db = load(SCANS, { scans: [], results: [] });
  const scan = (db.scans || []).find((s) => s.id === req.params.id);
  if (!scan) return fail(res, 404, "not_found", "scan not found");
  const text = String(req.body?.text || req.body?.content || "");
  if (!text) return fail(res, 400, "bad_request", "text required");
  if (githubDbEnabled()) {
    try {
      await putTextFile(`scans/artifacts/${scan.id}.txt`, text, `artifact ${scan.id}`);
    } catch (e) {
      return fail(res, 502, "github_error", e.message);
    }
  }
  return ok(res, { stored: true, path: `scans/artifacts/${scan.id}.txt` });
});


/** Phase 5 — player device runs passive deep scan and stores text result for owner */
app.post("/v1/player/scan/run", auth, async (req, res) => {
  try {
  if (req.user.role !== "player" && req.user.role !== "owner" && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "player token required");
  }
  if (req.user.role === "player" && Array.isArray(req.user.scope) && !req.user.scope.includes("scan:write")) {
    return fail(res, 403, "forbidden", "token scope scan:write required");
  }
  const db = load(SCANS, { scans: [], results: [] });
  const playerUsername = req.user.username || req.body?.username || "player";
  const ownerId = req.user.ownerId || req.body?.ownerId || req.user.sub;
  const clientSignals = Array.isArray(req.body?.signals) ? req.body.signals : [];

  const scan = {
    id: randomBytes(8).toString("hex"),
    ownerId,
    playerUsername,
    status: "running",
    mode: "deep_v3_hard",
    createdAt: new Date().toISOString(),
    signals: [],
    note: "player_passive_upload",
  };
  for (const s of clientSignals.slice(0, 300)) {
    scan.signals.push({
      type: String(s.type || "unknown").slice(0, 64),
      payload: s.payload || s,
      at: new Date().toISOString(),
    });
  }
  // Always add server-side meta signal from client build info
  if (req.body?.device) {
    scan.signals.push({ type: "build", payload: req.body.device, at: new Date().toISOString() });
  }
  db.scans = db.scans || [];
  db.scans.unshift(scan);

  const analysis = deepAnalyze(scan);
  scan.status = "completed";
  scan.completedAt = new Date().toISOString();
  scan.score = analysis.score;
  scan.verdict = analysis.verdict;
  scan.analysis = analysis;

  const textLines = [
    "=== DIV INTEGRITY SCAN REPORT ===",
    `engine=${analysis.engine || "deep_v3_hard"}`,
    `scanId=${scan.id}`,
    `player=${playerUsername}`,
    `ownerId=${ownerId}`,
    `score=${analysis.score}`,
    `verdict=${analysis.verdict}`,
    `signalCount=${analysis.signalCount}`,
    `typeCount=${analysis.typeCount}`,
    `riskPkgHits=${analysis.riskPkgHits != null ? analysis.riskPkgHits : 0}`,
    `createdAt=${scan.createdAt}`,
    "--- findings ---",
    ...analysis.findings.slice(0, 40).map((f) => `[${f.cat}] +${f.weight} ${f.detail}`),
    "=== END ===",
  ];
  const textContent = textLines.join("\n");
  db.results = db.results || [];
  db.results.unshift({
    id: randomBytes(8).toString("hex"),
    ownerId,
    playerUsername,
    label: `deep_scan_${playerUsername}_${scan.id}.txt`,
    textContent,
    bytes: Buffer.byteLength(textContent, "utf8"),
    createdAt: new Date().toISOString(),
    scanId: scan.id,
    score: analysis.score,
    verdict: analysis.verdict,
  });
  db.results = db.results.slice(0, 200);
  // Purge heavy signals after analysis (keep DB light)
  scan.signals = [];
  scan.purgedAt = new Date().toISOString();
  saveScans(db);
  if (githubDbEnabled()) {
    putTextFile(`scans/artifacts/${scan.id}.txt`, textContent, `player scan ${scan.id}`)
      .catch((e) => console.error("artifact", e.message));
  }

  // Phase 11 — AI heavy triage for elevated scores (no secrets)
  let triageSummary = null;
  if (analysis.score >= 30) {
    try {
      const AI = process.env.AI_HEAVY_URL || "https://div-ai-heavy.onrender.com";
      const payload = {
        score: analysis.score,
        verdict: analysis.verdict,
        playerUsername,
        findings: (analysis.findings || []).slice(0, 20).map((f) => ({
          cat: f.cat, detail: String(f.detail || "").slice(0, 100), weight: f.weight,
        })),
      };
      // fire-and-forget style with short timeout via AbortSignal if available
      const ac = typeof AbortController !== "undefined" ? new AbortController() : null;
      const timer = ac ? setTimeout(() => ac.abort(), 8000) : null;
      const tr = await fetch(`${AI.replace(/\/$/, "")}/v1/triage/text`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: req.headers.authorization || "",
        },
        body: JSON.stringify(payload),
        signal: ac ? ac.signal : undefined,
      });
      if (timer) clearTimeout(timer);
      if (tr.ok) {
        const tj = await tr.json();
        triageSummary = tj?.data?.triage?.summary || tj?.triage?.summary || null;
        // attach to latest result row
        if (db.results && db.results[0] && triageSummary) {
          db.results[0].triageSummary = triageSummary;
          saveScans(db);
        }
      }
    } catch (e) {
      console.error("triage bridge", e.message);
    }
  }

  return ok(res, {
    scanId: scan.id,
    score: analysis.score,
    verdict: analysis.verdict,
    findings: analysis.findings.slice(0, 15),
    resultLabel: `deep_scan_${playerUsername}_${scan.id}.txt`,
    triageSummary,
  });
  } catch (e) {
    console.error("player scan run", e);
    return fail(res, 500, "scan_error", e.message || "scan failed");
  }
});


/** Phase 9 — admin scan feed (all owners / players) */
app.get("/v1/admin/scans", auth, (req, res) => {
  if (req.user.role !== "admin") return fail(res, 403, "forbidden", "admin only");
  const db = load(SCANS, { scans: [], results: [] });
  const verdict = String(req.query.verdict || "").trim();
  let list = db.results || [];
  if (verdict) {
    list = list.filter((r) => String(r.verdict || "").toLowerCase().includes(verdict.toLowerCase()));
  }
  list = list.slice(0, 80).map((r) => ({
    id: r.id,
    ownerId: r.ownerId,
    playerUsername: r.playerUsername,
    label: r.label,
    score: r.score,
    verdict: r.verdict,
    createdAt: r.createdAt,
    scanId: r.scanId,
    bytes: r.bytes,
  }));
  return ok(res, { results: list, count: list.length });
});

app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 ${SERVICE} Phase 4 (deep) on :${PORT}`);
});