/**
 * Rate limit + security headers + path firewall
 */
const buckets = new Map();

export function rateLimit({ windowMs = 60_000, max = 60, keyFn } = {}) {
  return (req, res, next) => {
    const key = (keyFn ? keyFn(req) : null) || req.ip || req.headers["x-forwarded-for"] || "unknown";
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || now - b.start > windowMs) {
      b = { start: now, count: 0 };
      buckets.set(key, b);
    }
    b.count += 1;
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - b.count)));
    if (b.count > max) {
      return res.status(429).json({
        ok: false,
        error: { code: "rate_limited", message: "Too many requests" },
      });
    }
    next();
  };
}

const BLOCKED_PATHS = [
  /^\/\.env/i,
  /^\/\.git/i,
  /^\/wp-admin/i,
  /^\/wp-login/i,
  /^\/phpmyadmin/i,
  /^\/admin\.php/i,
  /^\/xmlrpc\.php/i,
  /\.\./,
  /%2e%2e/i,
];

export function pathFirewall(req, res, next) {
  const p = req.path || "";
  for (const re of BLOCKED_PATHS) {
    if (re.test(p) || re.test(req.url || "")) {
      return res.status(403).json({ ok: false, error: { code: "forbidden_path", message: "blocked" } });
    }
  }
  next();
}

export function securityHeaders(req, res, next) {
  res.removeHeader("X-Powered-By");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("X-Service-Policy", "passive-scan-only");
  res.setHeader("X-XSS-Protection", "0");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  // Allow inline CSS/JS for admin UI; API JSON still fine
  const isApi = (req.path || "").startsWith("/v1/") || (req.path || "") === "/health" || (req.path || "") === "/ready";
  if (isApi) {
    res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  } else {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://*.onrender.com; frame-ancestors 'none'; base-uri 'none'"
    );
  }
  next();
}

export function applySecurity(app) {
  app.disable("x-powered-by");
  app.use(pathFirewall);
  app.use(securityHeaders);
  app.use(rateLimit({ windowMs: 60_000, max: 90 }));
}

setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) {
    if (now - b.start > 5 * 60_000) buckets.delete(k);
  }
}, 60_000).unref?.();
