/**
 * Phase 9 — div-ai-heavy
 * Heavy job queue: APK sample analysis via GitHub Actions dispatch (optional)
 * Token never returned to clients. Encrypted-at-rest style: env only.
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
app.use(express.json({ limit: "3mb" }));

const PORT = process.env.PORT || 3000;
const SERVICE = "div-ai-heavy";
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-div-auth";
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "";
const GH_OWNER = process.env.GITHUB_OWNER || "web-coder-lab";
const GH_REPO = process.env.GITHUB_HEAVY_REPO || "div-integrity-jobs";
const GH_WORKFLOW = process.env.GITHUB_WORKFLOW || "analyze.yml";
const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });
const JOBS = join(DATA, "jobs.json");

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

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return fail(res, 403, "forbidden", `requires ${roles.join("|")}`);
    }
    next();
  };
}

/** Local static-ish analysis when GitHub not configured */
function localStubAnalyze({ packageName, sha256, note }) {
  const findings = [];
  let score = 10;
  const n = `${packageName || ""} ${note || ""}`.toLowerCase();
  if (/hack|cheat|aimbot|esp|inject|mod/.test(n)) {
    findings.push("name_or_note_risk_keywords");
    score += 40;
  }
  if (sha256) findings.push("hash_recorded");
  findings.push("local_stub_no_decompile");
  const verdict = score >= 60 ? "suspicious_package" : "needs_deep_analysis";
  return {
    engine: "local_stub",
    score: Math.min(100, score),
    verdict,
    findings,
    summary: GH_TOKEN
      ? "GitHub configured but local stub used for this path"
      : "GitHub token not set — local stub only. Set GITHUB_TOKEN + workflow for real decompile jobs.",
  };
}

async function dispatchGithubJob(job) {
  if (!GH_TOKEN) return { dispatched: false, reason: "GITHUB_TOKEN not set" };
  const url = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/actions/workflows/${GH_WORKFLOW}/dispatches`;
  const body = {
    ref: "main",
    inputs: {
      job_id: job.id,
      package_name: job.packageName || "",
      sha256: job.sha256 || "",
      note: (job.note || "").slice(0, 200),
      sample_url: job.sampleUrl || "",
      callback_url: process.env.PUBLIC_URL || "https://div-ai-heavy.onrender.com",
    },
  };
  const r = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${GH_TOKEN}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify(body),
  });
  if (r.status === 204 || r.ok) {
    return { dispatched: true, owner: GH_OWNER, repo: GH_REPO, workflow: GH_WORKFLOW };
  }
  const text = await r.text();
  console.error("gh dispatch fail", r.status, text.slice(0, 300));
  return { dispatched: false, status: r.status, body: text.slice(0, 300) };
}

app.get("/ready", (_req, res) => {
  res.json({ ready: true, service: typeof SERVICE !== "undefined" ? SERVICE : "ok" });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: SERVICE,
    phase: 9,
    githubConfigured: !!GH_TOKEN,
    heavyRepo: GH_TOKEN ? `${GH_OWNER}/${GH_REPO}` : null,
    time: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
  });
});

app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    phase: 9,
    group: "D — AI Workspace heavy",
    endpoints: [
      "POST /v1/jobs/apk",
      "POST /v1/jobs/:id/result",
      "GET  /v1/jobs/:id",
      "GET  /v1/jobs/mine",
      "GET  /v1/jobs/status",
    ],
    policy: "APK sample jobs only with prior consent path; token never exposed to clients",
  });
});

app.get("/v1/jobs/status", (_req, res) => {
  ok(res, {
    githubConfigured: !!GH_TOKEN,
    owner: GH_OWNER,
    repo: GH_REPO,
    workflow: GH_WORKFLOW,
    mode: GH_TOKEN ? "github_dispatch_or_stub" : "local_stub_only",
  });
});

/**
 * Enqueue APK / sample heavy job
 * body: { packageName, sha256?, note?, sampleUrl?, observeId?, scanId? }
 * Do NOT send full APK bytes here on free tier — hash + optional URL
 */
app.post("/v1/jobs/apk", auth, async (req, res) => {
  const packageName = String(req.body?.packageName || "").slice(0, 200);
  const sha256 = req.body?.sha256 ? String(req.body.sha256).slice(0, 64) : null;
  const note = String(req.body?.note || "").slice(0, 300);
  const sampleUrl = req.body?.sampleUrl ? String(req.body.sampleUrl).slice(0, 500) : null;
  if (!packageName && !sha256) {
    return fail(res, 400, "bad_request", "packageName or sha256 required");
  }

  const db = load(JOBS, { items: [] });
  const id = randomBytes(8).toString("hex");
  const job = {
    id,
    type: "apk_analysis",
    status: "queued",
    userId: req.user.sub,
    role: req.user.role,
    packageName: packageName || null,
    sha256,
    note,
    sampleUrl,
    observeId: req.body?.observeId ? String(req.body.observeId) : null,
    scanId: req.body?.scanId ? String(req.body.scanId) : null,
    result: null,
    github: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  // Try GitHub dispatch
  const gh = await dispatchGithubJob(job);
  job.github = {
    dispatched: gh.dispatched,
    reason: gh.reason || null,
    status: gh.status || null,
    // never store token
  };

  if (!gh.dispatched) {
    // Immediate local stub result so pipeline is not blocked
    job.status = "completed_stub";
    job.result = localStubAnalyze(job);
    job.completedAt = new Date().toISOString();
  } else {
    job.status = "dispatched";
  }
  job.updatedAt = new Date().toISOString();

  db.items.unshift(job);
  db.items = db.items.slice(0, 200);
  save(JOBS, db);

  return ok(res, {
    job: {
      id: job.id,
      status: job.status,
      packageName: job.packageName,
      sha256: job.sha256,
      githubDispatched: job.github?.dispatched || false,
      result: job.result,
    },
  }, 201);
});

/**
 * Callback from GitHub Action / runner with analysis result
 * Protected by shared secret header X-Job-Secret or admin JWT
 */
app.post("/v1/jobs/:id/result", async (req, res) => {
  const secret = process.env.JOB_CALLBACK_SECRET || "";
  const headerSecret = req.headers["x-job-secret"];
  let authed = false;
  if (secret && headerSecret && headerSecret === secret) authed = true;
  if (!authed) {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    const payload = verifyJwt(token);
    if (payload && (payload.role === "admin" || payload.role === "owner")) authed = true;
  }
  if (!authed) return fail(res, 401, "unauthorized", "job callback auth failed");

  const db = load(JOBS, { items: [] });
  const idx = db.items.findIndex((j) => j.id === req.params.id);
  if (idx < 0) return fail(res, 404, "not_found", "job not found");

  const job = db.items[idx];
  job.status = "completed";
  job.result = {
    engine: req.body?.engine || "github_runner",
    score: Math.min(100, Number(req.body?.score) || 0),
    verdict: req.body?.verdict || "unknown",
    findings: Array.isArray(req.body?.findings) ? req.body.findings.slice(0, 50) : [],
    summary: String(req.body?.summary || "").slice(0, 1000),
  };
  job.completedAt = new Date().toISOString();
  job.updatedAt = job.completedAt;
  db.items[idx] = job;
  save(JOBS, db);
  return ok(res, { job: { id: job.id, status: job.status, result: job.result } });
});

app.get("/v1/jobs/:id", auth, (req, res) => {
  const db = load(JOBS, { items: [] });
  const job = db.items.find((j) => j.id === req.params.id);
  if (!job) return fail(res, 404, "not_found", "job not found");
  if (job.userId !== req.user.sub && req.user.role !== "admin") {
    return fail(res, 403, "forbidden", "not your job");
  }
  return ok(res, {
    job: {
      id: job.id,
      type: job.type,
      status: job.status,
      packageName: job.packageName,
      sha256: job.sha256,
      result: job.result,
      githubDispatched: job.github?.dispatched || false,
      createdAt: job.createdAt,
      completedAt: job.completedAt,
    },
  });
});

app.get("/v1/jobs/mine", auth, (req, res) => {
  const db = load(JOBS, { items: [] });
  const list = db.items
    .filter((j) => j.userId === req.user.sub || req.user.role === "admin")
    .slice(0, 50)
    .map((j) => ({
      id: j.id,
      status: j.status,
      packageName: j.packageName,
      verdict: j.result?.verdict,
      score: j.result?.score,
      createdAt: j.createdAt,
    }));
  return ok(res, { jobs: list });
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


/** Phase 11 — text triage (no secrets, summary only) */
function heuristicTriage({ score, verdict, findings, playerUsername }) {
  const sc = Math.min(100, Math.max(0, Number(score) || 0));
  const inds = (findings || []).slice(0, 12).map((f) => ({
    cat: f.cat || "meta",
    detail: String(f.detail || "").slice(0, 120),
    weight: f.weight,
  }));
  let summary;
  if (sc >= 55) {
    summary = `High risk environment for player ${playerUsername || "unknown"} (score ${sc}). Multiple integrity signals suggest cheat tooling, hooks, or emulated/rooted device. Review findings before tournament entry.`;
  } else if (sc >= 30) {
    summary = `Suspicious signals for player ${playerUsername || "unknown"} (score ${sc}). Not definitive; recommend rescan and manual review of package/accessibility indicators.`;
  } else if (sc >= 12) {
    summary = `Low-risk residual signals for player ${playerUsername || "unknown"} (score ${sc}). Typically benign device noise; keep monitoring.`;
  } else {
    summary = `No strong integrity risk for player ${playerUsername || "unknown"} (score ${sc}). Passive remains passive and non-conclusive alone.`;
  }
  return {
    score: sc,
    verdict: verdict || (sc >= 55 ? "likely_cheat_environment" : sc >= 30 ? "suspicious" : sc >= 12 ? "low_risk_signals" : "clean_or_unclear"),
    summary,
    indicators: inds,
    engine: "heuristic_triage_v1",
    secretsRedacted: true,
  };
}

app.post("/v1/triage/text", auth, async (req, res) => {
  const body = req.body || {};
  // Never accept raw API keys / passwords in triage payload storage
  const findings = Array.isArray(body.findings) ? body.findings.slice(0, 40) : [];
  const out = heuristicTriage({
    score: body.score,
    verdict: body.verdict,
    findings,
    playerUsername: String(body.playerUsername || "").slice(0, 40),
  });
  // Optional: dispatch heavy job only for high scores when GitHub configured
  let heavy = null;
  if ((out.score >= 55) && process.env.GITHUB_TOKEN) {
    try {
      heavy = await dispatchGithubJob({
        id: "triage-" + Date.now().toString(36),
        type: "scan_triage",
        playerUsername: body.playerUsername,
        score: out.score,
        verdict: out.verdict,
        createdAt: new Date().toISOString(),
      });
    } catch (e) {
      heavy = { dispatched: false, reason: e.message };
    }
  }
  return ok(res, { triage: out, heavy });
});

app.post("/v1/triage/popup", auth, async (req, res) => {
  const out = heuristicTriage({
    score: req.body?.score,
    verdict: req.body?.verdict,
    findings: Array.isArray(req.body?.findings) ? req.body.findings.slice(0, 20) : [],
    playerUsername: String(req.body?.playerUsername || "").slice(0, 40),
  });
  return ok(res, {
    title: out.score >= 55 ? "High risk" : out.score >= 30 ? "Suspicious" : "Scan result",
    body: out.summary,
    triage: out,
  });
});

app.post("/v1/triage/scan-result", auth, async (req, res) => {
  // Same as text — explicit alias for deep-a bridge
  req.url = "/v1/triage/text";
  const out = heuristicTriage({
    score: req.body?.score,
    verdict: req.body?.verdict,
    findings: Array.isArray(req.body?.findings) ? req.body.findings.slice(0, 40) : [],
    playerUsername: String(req.body?.playerUsername || "").slice(0, 40),
  });
  return ok(res, { triage: out });
});


app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 ${SERVICE} Phase 9 on :${PORT} gh=${!!GH_TOKEN}`);
});