import nodemailer from "nodemailer";
import { createHmac } from "crypto";

const host = process.env.SMTP_HOST || "smtp.gmail.com";
const port = Number(process.env.SMTP_PORT || 465);
const user = process.env.SMTP_USER || "";
const pass = (process.env.SMTP_PASS || "").replace(/\s+/g, "");
const from = process.env.SMTP_FROM || user || "noreply@div-integrity.local";
const MAIL_URL = (process.env.MAIL_URL || "").replace(/\/$/, "");
const MAIL_API_KEY = process.env.MAIL_API_KEY || "";
const SERVICE_SECRET = process.env.SERVICE_SECRET || process.env.JWT_SECRET || "";
const SERVICE_NAME = process.env.SERVICE_NAME || "div-auth";

export function mailConfigured() {
  return Boolean((user && pass) || MAIL_URL);
}

async function sendViaGateway(to, subject, html, text) {
  const ts = String(Date.now());
  const path = "/v1/send";
  const method = "POST";
  const base = `${SERVICE_NAME}.${ts}.${method}.${path}`;
  const sig = createHmac("sha256", SERVICE_SECRET).update(base).digest("hex");
  const r = await fetch(MAIL_URL + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Service-Name": SERVICE_NAME,
      "X-Service-Timestamp": ts,
      "X-Service-Signature": sig,
      "X-Mail-Key": MAIL_API_KEY,
    },
    body: JSON.stringify({ to, subject, html, text }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j?.ok) {
    return { ok: false, mode: "gateway_error", error: j?.error?.message || j?.data?.error || `http_${r.status}` };
  }
  return { ok: !!j.data?.sent, mode: "gateway", id: j.data?.id, error: j.data?.error };
}

let transporter = null;
function getTransport() {
  if (!(user && pass)) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      service: process.env.SMTP_SERVICE || "gmail",
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
      connectionTimeout: 12000,
      greetingTimeout: 12000,
      socketTimeout: 15000,
      tls: { minVersion: "TLSv1.2" },
    });
  }
  return transporter;
}

export async function sendOtpEmail(to, code) {
  const html = `<div style="font-family:system-ui,sans-serif;max-width:480px">
    <h2>Div Integrity — Email verification</h2>
    <p>Your OTP code is:</p>
    <p style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</p>
    <p style="color:#666">Expires in 10 minutes.</p></div>`;
  return sendHtmlEmail(to, "Your Div Integrity OTP", html, `Your OTP is ${code}`);
}

export async function sendHtmlEmail(to, subject, html, text) {
  // Prefer dedicated mail server if configured
  if (MAIL_URL) {
    try {
      return await sendViaGateway(to, subject, html, text || subject);
    } catch (e) {
      console.error("mail gateway", e.message);
      // fall through to local smtp
    }
  }
  const t = getTransport();
  if (!t) return { ok: false, mode: "log", error: "smtp_not_configured", devCode: undefined };
  try {
    const info = await Promise.race([
      t.sendMail({ from: from || user, to, subject, text: text || subject, html }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("smtp_timeout")), 15000)),
    ]);
    return { ok: true, mode: "smtp", id: info.messageId };
  } catch (e) {
    console.error("smtp", e.message);
    return { ok: false, mode: "error", error: e.message };
  }
}
