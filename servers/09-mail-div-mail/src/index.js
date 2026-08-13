import express from "express";
import cors from "cors";
import nodemailer from "nodemailer";
import { createHmac, timingSafeEqual } from "crypto";
import { applySecurity, rateLimit } from "./hardening.js";

const PORT = Number(process.env.PORT || 3010);
const SERVICE = "div-mail";
const SERVICE_SECRET = process.env.SERVICE_SECRET || process.env.JWT_SECRET || "dev-change-me";
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = (process.env.SMTP_PASS || "").replace(/\s+/g, "");
const SMTP_HOST = process.env.SMTP_HOST || "smtp.gmail.com";
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const ALLOW_PUBLIC = process.env.MAIL_ALLOW_PUBLIC === "1";
const MAIL_API_KEY = process.env.MAIL_API_KEY || "";

const app = express();
app.set("trust proxy", 1);
applySecurity(app);
app.use(cors({ origin: true }));
app.use(express.json({ limit: "256kb" }));

const sendLimit = rateLimit({
  windowMs: 60_000,
  max: 20,
  keyFn: (req) => req.ip + ":mail",
});

function ok(res, data, status = 200) {
  return res.status(status).json({ ok: true, data, version: "v1", service: SERVICE });
}
function fail(res, status, code, message) {
  return res.status(status).json({ ok: false, error: { code, message }, service: SERVICE });
}

function mailConfigured() {
  return Boolean(SMTP_USER && SMTP_PASS);
}

let transporter = null;
function getTransport() {
  if (!mailConfigured()) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      service: process.env.SMTP_SERVICE || "gmail",
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
      connectionTimeout: 20000,
      greetingTimeout: 20000,
      socketTimeout: 25000,
      tls: { minVersion: "TLSv1.2" },
    });
  }
  return transporter;
}

function serviceAuth(req, res, next) {
  if (ALLOW_PUBLIC) return next();
  const key = req.headers["x-mail-key"] || req.headers["authorization"]?.replace(/^Bearer\s+/i, "") || "";
  if (MAIL_API_KEY && key && key === MAIL_API_KEY) return next();
  const name = req.headers["x-service-name"] || "";
  const ts = req.headers["x-service-timestamp"] || "";
  const sig = req.headers["x-service-signature"] || "";
  if (!name || !ts || !sig) return fail(res, 401, "unauthorized", "service auth required");
  const age = Math.abs(Date.now() - Number(ts));
  if (!Number.isFinite(age) || age > 5 * 60_000) return fail(res, 401, "unauthorized", "timestamp skew");
  const base = `${name}.${ts}.${req.method}.${req.path}`;
  const expect = createHmac("sha256", SERVICE_SECRET).update(base).digest("hex");
  try {
    const a = Buffer.from(expect);
    const b = Buffer.from(String(sig));
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return fail(res, 401, "unauthorized", "bad signature");
    }
  } catch {
    return fail(res, 401, "unauthorized", "bad signature");
  }
  next();
}

async function sendMail({ to, subject, html, text }) {
  const t = getTransport();
  if (!t) return { ok: false, error: "smtp_not_configured" };
  try {
    const info = await Promise.race([
      t.sendMail({
        from: SMTP_FROM || SMTP_USER,
        to,
        subject,
        text: text || subject,
        html: html || `<pre>${text || subject}</pre>`,
      }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("smtp_timeout")), 22000)),
    ]);
    return { ok: true, id: info.messageId };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: SERVICE,
    phase: 13,
    smtpConfigured: mailConfigured(),
    smtpHost: SMTP_HOST,
    smtpPort: SMTP_PORT,
    from: SMTP_FROM ? SMTP_FROM.replace(/(.{2}).+(@.+)/, "$1***$2") : null,
    time: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
  });
});
app.get("/ready", (_req, res) => res.json({ ready: true, service: SERVICE }));
app.get("/", (_req, res) => {
  res.json({
    service: SERVICE,
    role: "Dedicated SMTP / HTML email gateway",
    endpoints: [
      "POST /v1/send",
      "POST /v1/send-otp",
      "POST /v1/send-template",
      "GET /health",
    ],
  });
});

/** Generic HTML email */
app.post("/v1/send", sendLimit, serviceAuth, async (req, res) => {
  const to = String(req.body?.to || "").trim().toLowerCase();
  const subject = String(req.body?.subject || "").slice(0, 200);
  const html = String(req.body?.html || "");
  const text = String(req.body?.text || "");
  if (!to.includes("@")) return fail(res, 400, "bad_email", "valid to required");
  if (!subject) return fail(res, 400, "bad_subject", "subject required");
  if (!html && !text) return fail(res, 400, "bad_body", "html or text required");
  const r = await sendMail({ to, subject, html, text });
  if (!r.ok) return ok(res, { sent: false, error: r.error });
  return ok(res, { sent: true, id: r.id, to, subject });
});

app.post("/v1/send-otp", sendLimit, serviceAuth, async (req, res) => {
  const to = String(req.body?.to || "").trim().toLowerCase();
  const code = String(req.body?.code || "").slice(0, 12);
  if (!to.includes("@") || !code) return fail(res, 400, "bad_request", "to and code required");
  const html = `<div style="font-family:system-ui,sans-serif;max-width:480px">
    <h2>Div Integrity — OTP</h2>
    <p style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</p>
    <p style="color:#666">Expires in 10 minutes.</p></div>`;
  const r = await sendMail({ to, subject: "Your Div Integrity OTP", html, text: `OTP: ${code}` });
  return ok(res, { sent: !!r.ok, id: r.id, error: r.error || null });
});

app.post("/v1/send-template", sendLimit, serviceAuth, async (req, res) => {
  const to = String(req.body?.to || "").trim().toLowerCase();
  const template = String(req.body?.template || "approval");
  const name = String(req.body?.name || "User");
  const message = String(req.body?.message || "");
  if (!to.includes("@")) return fail(res, 400, "bad_email", "valid to required");

  let subject, html;
  if (template === "remove") {
    subject = "Div Integrity — Access removed";
    html = `<div style="font-family:system-ui,sans-serif;max-width:520px">
      <h2 style="color:#b91c1c">You are removed</h2>
      <p>Please open the app and read the admin message.</p>
      <div style="padding:12px;border-radius:8px;background:#fef2f2;border:1px solid #fecaca">
        <h3 style="margin:0 0 8px">Lock Panel</h3>
        <div>${message || "<p>Your owner access was removed by admin.</p>"}</div>
      </div></div>`;
  } else if (template === "otp") {
    const code = String(req.body?.code || "");
    subject = "Your Div Integrity OTP";
    html = `<div style="font-family:system-ui,sans-serif"><h2>OTP</h2>
      <p style="font-size:28px;font-weight:700">${code}</p></div>`;
  } else {
    subject = "Div Integrity — Owner approved";
    html = `<div style="font-family:system-ui,sans-serif;max-width:520px">
      <h2 style="color:#047857">Approval successful</h2>
      <p>Hi ${name}, admin approved your owner account.</p>
      <p>Open the Owner app for dashboard and referral code.</p></div>`;
  }
  const r = await sendMail({ to, subject, html, text: subject });
  return ok(res, { sent: !!r.ok, id: r.id, template, error: r.error || null });
});

app.use((req, res) => fail(res, 404, "not_found", `no route ${req.method} ${req.path}`));
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 div-mail on :${PORT} smtp=${mailConfigured()}`);
});
