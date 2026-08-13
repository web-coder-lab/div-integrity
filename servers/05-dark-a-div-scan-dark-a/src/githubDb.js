/**
 * GitHub = primary durable database for Div Integrity
 */
const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "";
const OWNER = process.env.GITHUB_OWNER || "web-coder-lab";
const REPO = process.env.GITHUB_DATA_REPO || "div-integrity-data";
const BRANCH = process.env.GITHUB_DATA_BRANCH || "main";
const API = "https://api.github.com";

export function githubDbEnabled() {
  return Boolean(TOKEN && OWNER && REPO);
}

async function gh(path, { method = "GET", body } = {}) {
  if (!githubDbEnabled()) throw new Error("github_db_disabled");
  const r = await fetch(`${API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
      "User-Agent": "div-integrity-db",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { raw: text }; }
  if (!r.ok) {
    const err = new Error(json?.message || `github_${r.status}`);
    err.status = r.status;
    err.body = json;
    throw err;
  }
  return json;
}

async function getFileMeta(path) {
  try {
    return await gh(`/repos/${OWNER}/${REPO}/contents/${encodeURI(path)}?ref=${BRANCH}`);
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}

export async function getJsonFile(path) {
  const f = await getFileMeta(path);
  if (!f || !f.content) return null;
  const raw = Buffer.from(String(f.content).replace(/\n/g, ""), "base64").toString("utf8");
  return JSON.parse(raw);
}

export async function putJsonFile(path, data, message = "sync") {
  const content = Buffer.from(JSON.stringify(data, null, 2), "utf8").toString("base64");
  const existing = await getFileMeta(path);
  const body = {
    message: String(message).slice(0, 80),
    content,
    branch: BRANCH,
  };
  if (existing?.sha) body.sha = existing.sha;
  return gh(`/repos/${OWNER}/${REPO}/contents/${encodeURI(path)}`, { method: "PUT", body });
}

export async function putTextFile(path, text, message = "sync text") {
  const content = Buffer.from(String(text), "utf8").toString("base64");
  const existing = await getFileMeta(path);
  const body = { message: String(message).slice(0, 80), content, branch: BRANCH };
  if (existing?.sha) body.sha = existing.sha;
  return gh(`/repos/${OWNER}/${REPO}/contents/${encodeURI(path)}`, { method: "PUT", body });
}

export async function deleteFile(path, message = "cleanup") {
  const existing = await getFileMeta(path);
  if (!existing?.sha) return { deleted: false, reason: "missing" };
  await gh(`/repos/${OWNER}/${REPO}/contents/${encodeURI(path)}`, {
    method: "DELETE",
    body: { message: String(message).slice(0, 80), sha: existing.sha, branch: BRANCH },
  });
  return { deleted: true, path };
}

/** Pull from GitHub if local missing/empty */
export async function hydrateLocalJson(localPath, remotePath, writeFileSync, existsSync, readFileSync) {
  if (!githubDbEnabled()) return { hydrated: false };
  try {
    let need = !existsSync(localPath);
    if (!need) {
      try {
        const cur = JSON.parse(readFileSync(localPath, "utf8"));
        const empty =
          !cur ||
          (Array.isArray(cur.users) && cur.users.length === 0) ||
          (Array.isArray(cur.owners) && cur.owners.length === 0);
        // only hydrate users/owners if empty
        if (remotePath.includes("users") || remotePath.includes("owners")) need = empty;
        else need = false;
      } catch {
        need = true;
      }
    }
    if (!need) return { hydrated: false, reason: "local_ok" };
    const data = await getJsonFile(remotePath);
    if (!data) return { hydrated: false, reason: "remote_missing" };
    writeFileSync(localPath, JSON.stringify(data, null, 2));
    return { hydrated: true, remotePath };
  } catch (e) {
    return { hydrated: false, error: e.message };
  }
}
