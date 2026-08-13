/**
 * Phase 3 — Service-to-service auth helpers
 * Header: X-Service-Name + X-Service-Timestamp + X-Service-Signature
 * Signature = HMAC-SHA256(serviceSecret, `${name}.${timestamp}.${method}.${path}.${bodyHash}`)
 */
import { createHmac, createHash, timingSafeEqual } from "crypto";

const MAX_SKEW_MS = 5 * 60 * 1000;

export function bodyHash(body) {
  const raw = typeof body === "string" ? body : JSON.stringify(body ?? "");
  return createHash("sha256").update(raw).digest("hex");
}

export function signServiceRequest({ serviceName, serviceSecret, method, path, body, timestamp }) {
  const ts = String(timestamp || Date.now());
  const bh = bodyHash(body ?? "");
  const payload = `${serviceName}.${ts}.${method.toUpperCase()}.${path}.${bh}`;
  const sig = createHmac("sha256", serviceSecret).update(payload).digest("hex");
  return { timestamp: ts, signature: sig, bodyHash: bh };
}

export function verifyServiceRequest(req, { serviceSecret, allowedServices }) {
  const name = req.headers["x-service-name"];
  const ts = req.headers["x-service-timestamp"];
  const sig = req.headers["x-service-signature"];
  if (!name || !ts || !sig) return { ok: false, code: "missing_service_auth" };
  if (allowedServices?.length && !allowedServices.includes(name)) {
    return { ok: false, code: "service_not_allowed" };
  }
  const t = Number(ts);
  if (!Number.isFinite(t) || Math.abs(Date.now() - t) > MAX_SKEW_MS) {
    return { ok: false, code: "timestamp_skew" };
  }
  const bh = createHash("sha256")
    .update(typeof req.rawBody === "string" ? req.rawBody : JSON.stringify(req.body ?? ""))
    .digest("hex");
  const path = req.originalUrl?.split("?")[0] || req.path;
  const payload = `${name}.${ts}.${req.method.toUpperCase()}.${path}.${bh}`;
  const expect = createHmac("sha256", serviceSecret).update(payload).digest("hex");
  try {
    const a = Buffer.from(expect, "hex");
    const b = Buffer.from(String(sig), "hex");
    if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, code: "bad_signature" };
  } catch {
    return { ok: false, code: "bad_signature" };
  }
  return { ok: true, serviceName: name };
}

export async function serviceFetch(baseUrl, path, { serviceName, serviceSecret, method = "GET", body } = {}) {
  const url = `${baseUrl.replace(/\/$/, "")}${path}`;
  const ts = Date.now();
  const { signature } = signServiceRequest({
    serviceName,
    serviceSecret,
    method,
    path,
    body,
    timestamp: ts,
  });
  const res = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-Service-Name": serviceName,
      "X-Service-Timestamp": String(ts),
      "X-Service-Signature": signature,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { status: res.status, data };
}
