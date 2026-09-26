import { createHash } from "crypto";

// ---------------------------------------------------------------------------
// Deterministic identity namespaces.
//
// A verified Pocket Edu account's in-game identities are derived from the
// verified `sub` claim through fixed namespaces (UUIDv5-style: SHA-1 over
// the namespace UUID bytes plus the name, with version/variant bits set).
// This module has no dependencies beyond node:crypto, so the adapter, the
// master, every worker, replacement workers, and fresh restarts all derive
// the *same* identity for the same account — no shared secret, no
// coordination, no environment needed.
//
// The three namespaces keep the identity classes disjoint by construction:
// for any input X, guest(X) != account(X) != public(X), and none of them
// equals X itself. In particular:
//
// - A guest presenting an account's raw subject UUID as their token gets
//   guest(subject), which differs from account(subject): the guest can
//   never become the account, take its lobby seat, or pass its
//   creator/reconnect checks (all of which compare persistentId exactly).
// - A guest presenting an account's *public* profile id gets
//   guest(publicId), which is likewise a different identity.
// - The public profile id (PUBLIC_NAMESPACE) is what other players see;
//   the authentication identity (ACCOUNT_NAMESPACE) never leaves the
//   server. Knowing the public id does not reveal the auth identity.
//
// These UUIDs are part of the identity contract: they must never change.
// ---------------------------------------------------------------------------
const GUEST_NAMESPACE = "b57ee7c3-9c97-49e3-be01-46729ea23699";
const ACCOUNT_NAMESPACE = "8c1f8a29-dc4a-4595-9879-9a255b174267";
const PUBLIC_NAMESPACE = "eae927e9-1645-4d70-9df5-9e38d1464ae7";

function uuidFromHash(namespaceUuid: string, name: string): string {
  const nsBytes = Buffer.from(namespaceUuid.replace(/-/g, ""), "hex");
  const digest = createHash("sha1")
    .update(nsBytes)
    .update(name, "utf8")
    .digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
  const hex = bytes.toString("hex");
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}` +
    `-${hex.slice(16, 20)}-${hex.slice(20)}`
  );
}

/**
 * Map a raw guest UUID into the guest identity namespace. Every caller
 * that accepts a guest token must use this before the id is compared,
 * stored, or checked against lobby ownership — the raw token must never
 * be used as an identity directly.
 */
export function deriveGuestPersistentId(rawGuestUuid: string): string {
  return uuidFromHash(GUEST_NAMESPACE, rawGuestUuid.toLowerCase());
}

/**
 * Derive the in-game authentication identity for a verified Pocket Edu
 * account. UUID-shaped (so existing UUID-typed fields keep validating),
 * deterministic across processes and restarts, and unforgeable without a
 * valid JWT: the account UUID (`sub`) is opaque and never exposed, so
 * nobody can compute this id except by presenting a signed token.
 */
export function deriveAccountPersistentId(accountUuid: string): string {
  return uuidFromHash(ACCOUNT_NAMESPACE, accountUuid.toLowerCase());
}

/**
 * Derive the account's *public* profile id: what /users/@me and lobby
 * player lists show. Deliberately different from the authentication
 * identity (deriveAccountPersistentId) — public profile ids are visible
 * to other players and must never double as credentials.
 */
export function deriveAccountPublicId(accountUuid: string): string {
  return uuidFromHash(PUBLIC_NAMESPACE, accountUuid.toLowerCase());
}
