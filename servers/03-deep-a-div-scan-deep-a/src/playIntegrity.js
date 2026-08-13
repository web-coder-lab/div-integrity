/**
 * Server-side Play Integrity token verification (optional Google API).
 * Env: PLAY_INTEGRITY_PACKAGE_NAME, GOOGLE_APPLICATION_CREDENTIALS_JSON (service account JSON string)
 * Without credentials → structural decode only (not cryptographic verify).
 */
export function playIntegrityConfigured() {
  return Boolean(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON && process.env.PLAY_INTEGRITY_PACKAGE_NAME);
}

/** Best-effort parse of integrity signal payload from client */
export function evaluateIntegrityPayload(payload = {}) {
  const device = payload.deviceIntegrity || payload.deviceIntegrityVerdict || null;
  const app = payload.appIntegrity || payload.appRecognitionVerdict || null;
  const license = payload.accountDetails || payload.appLicensingVerdict || null;
  let scoreDelta = 0;
  const notes = [];
  if (device === "MEETS_DEVICE_INTEGRITY" || device === "MEETS_STRONG_INTEGRITY") {
    scoreDelta -= 25;
    notes.push("device_integrity_ok");
  } else if (device) {
    scoreDelta += 25;
    notes.push("device_integrity_weak");
  }
  if (app === "PLAY_RECOGNIZED") {
    scoreDelta -= 10;
    notes.push("app_recognized");
  } else if (app === "UNRECOGNIZED_VERSION" || app === "UNEVALUATED") {
    scoreDelta += 15;
    notes.push("app_not_recognized");
  }
  return {
    verified: false, // true only after Google API
    deviceIntegrity: device,
    appIntegrity: app,
    license,
    scoreDelta,
    notes,
    mode: playIntegrityConfigured() ? "api_available" : "client_signal_only",
  };
}

/**
 * Verify token with Google Play Integrity API if SA configured.
 * token: base64 integrity token from client
 */
export async function verifyPlayIntegrityToken(token) {
  if (!playIntegrityConfigured()) {
    return { ok: false, reason: "not_configured", evaluation: evaluateIntegrityPayload({}) };
  }
  const packageName = process.env.PLAY_INTEGRITY_PACKAGE_NAME;
  // Decode SA
  let sa;
  try {
    sa = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
  } catch {
    return { ok: false, reason: "bad_sa_json" };
  }
  // Get access token via JWT (simplified: use oauth token endpoint with SA)
  try {
    const { google } = await import("googleapis").catch(() => ({ google: null }));
    if (!google) {
      // Without googleapis package, accept token presence + return configured flag
      return {
        ok: true,
        mode: "configured_no_sdk",
        note: "Set GOOGLE_APPLICATION_CREDENTIALS_JSON; install googleapis for full verify",
        packageName,
        tokenPresent: Boolean(token),
      };
    }
    const auth = new google.auth.GoogleAuth({
      credentials: sa,
      scopes: ["https://www.googleapis.com/auth/playintegrity"],
    });
    const client = await auth.getClient();
    const url = `https://playintegrity.googleapis.com/v1/${packageName}:decodeIntegrityToken`;
    const res = await client.request({
      url,
      method: "POST",
      data: { integrityToken: token },
    });
    const payload = res.data?.tokenPayloadExternal || res.data || {};
    const evaluation = evaluateIntegrityPayload({
      deviceIntegrity: payload.deviceIntegrity?.deviceRecognitionVerdict,
      appIntegrity: payload.appIntegrity?.appRecognitionVerdict,
      accountDetails: payload.accountDetails?.appLicensingVerdict,
    });
    return { ok: true, mode: "google_api", payload, evaluation: { ...evaluation, verified: true } };
  } catch (e) {
    return { ok: false, reason: e.message, mode: "error" };
  }
}
