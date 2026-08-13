import { randomBytes } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { putJsonFile, getJsonFile, githubDbEnabled, hydrateLocalJson } from "./githubDb.js";

const DATA = join(process.cwd(), ".data");
mkdirSync(DATA, { recursive: true });
const FILE = join(DATA, "owners.json");
let bootstrapped = false;

async function ensureHydrated() {
  if (bootstrapped) return;
  bootstrapped = true;
  try {
    const r = await hydrateLocalJson(FILE, "owners/owners.json", writeFileSync, existsSync, readFileSync);
    if (r.hydrated) console.log("owners hydrated from GitHub");
  } catch (e) {
    console.error("owners hydrate", e.message);
  }
}

// fire and forget at import
ensureHydrated();

function load() {
  if (!existsSync(FILE)) return { owners: [] };
  try { return JSON.parse(readFileSync(FILE, "utf8")); } catch { return { owners: [] }; }
}
function save(db) {
  writeFileSync(FILE, JSON.stringify(db, null, 2));
  if (githubDbEnabled()) {
    putJsonFile("owners/owners.json", db, "sync owners").catch((e) => console.error("owners gh", e.message));
  }
}

/** Force pull from GitHub (server restart recovery) */
export async function pullFromGithub() {
  try {
    const data = await getJsonFile("owners/owners.json");
    if (data && Array.isArray(data.owners)) {
      writeFileSync(FILE, JSON.stringify(data, null, 2));
      return { ok: true, count: data.owners.length };
    }
    return { ok: false, reason: "empty" };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

export function generateReferralCode() {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let body = "";
  const bytes = randomBytes(24);
  for (let i = 0; i < 24; i++) body += alphabet[bytes[i] % alphabet.length];
  return `ds_ff/${body}`;
}

export function listOwners() {
  return load().owners;
}

export function getOwnerById(id) {
  return load().owners.find((o) => o.id === id) || null;
}

export function getOwnerByEmail(email) {
  const e = String(email || "").toLowerCase();
  return load().owners.find((o) => o.email === e) || null;
}

export function getOwnerByReferral(code) {
  const c = String(code || "").trim();
  return load().owners.find((o) => o.referralCode === c && o.status === "approved") || null;
}

export function createOwnerRequest({ username, email, passwordHash, salt }) {
  const db = load();
  const emailL = String(email).toLowerCase();
  if (db.owners.some((o) => o.email === emailL)) return { error: "email_exists" };
  if (db.owners.some((o) => o.username === username)) return { error: "username_exists" };
  const owner = {
    id: randomBytes(8).toString("hex"),
    username: String(username).slice(0, 40),
    email: emailL,
    passwordHash,
    salt,
    status: "pending",
    referralCode: null,
    lockMessageHtml: null,
    createdAt: new Date().toISOString(),
    approvedAt: null,
    removedAt: null,
    users: [],
  };
  db.owners.unshift(owner);
  save(db);
  return { owner: publicOwner(owner) };
}

export function publicOwner(o, { includeReferral = false } = {}) {
  if (!o) return null;
  return {
    id: o.id,
    username: o.username,
    email: o.email,
    status: o.status,
    userCount: (o.users || []).length,
    createdAt: o.createdAt,
    approvedAt: o.approvedAt,
    removedAt: o.removedAt,
    lockMessageHtml: o.status === "removed" ? o.lockMessageHtml : undefined,
    referralCode: includeReferral && o.status === "approved" ? o.referralCode : undefined,
  };
}

export function verifyOwnerPassword(owner, password, verifyFn) {
  if (!owner) return false;
  return verifyFn(password, owner.passwordHash, owner.salt);
}

export function approveOwner(id) {
  const db = load();
  const o = db.owners.find((x) => x.id === id);
  if (!o) return { error: "not_found" };
  o.status = "approved";
  o.approvedAt = new Date().toISOString();
  o.removedAt = null;
  o.lockMessageHtml = null;
  if (!o.referralCode) o.referralCode = generateReferralCode();
  save(db);
  return { owner: publicOwner(o, { includeReferral: true }) };
}

export function removeOwner(id, lockMessageHtml) {
  const db = load();
  const o = db.owners.find((x) => x.id === id);
  if (!o) return { error: "not_found" };
  o.status = "removed";
  o.removedAt = new Date().toISOString();
  o.lockMessageHtml = lockMessageHtml || "<h2>Lock Panel</h2><p>Removed by admin</p>";
  save(db);
  return { owner: publicOwner(o) };
}

export function reapproveOwner(id) {
  return approveOwner(id);
}

export function listOwnerPlayers(ownerId) {
  const o = getOwnerById(ownerId);
  return o?.users || [];
}

export function attachUserToOwner(referralCode, username) {
  const db = load();
  const o = db.owners.find((x) => x.referralCode === referralCode && x.status === "approved");
  if (!o) return { error: "invalid_code" };
  const name = String(username).slice(0, 40);
  o.users = o.users || [];
  const exists = o.users.some((u) => (u.username || u) === name);
  if (!exists) {
    o.users.push({ username: name, joinedAt: new Date().toISOString() });
    save(db);
  }
  return {
    ok: true,
    ownerId: o.id,
    ownerUsername: o.username,
    username: name,
    alreadyJoined: exists,
  };
}

export function adminList() {
  return load().owners.map((o) => ({
    ...publicOwner(o, { includeReferral: true }),
    userCount: (o.users || []).length,
  }));
}
