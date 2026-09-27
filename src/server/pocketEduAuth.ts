import { importJWK, jwtVerify } from "jose";
import {
  TokenPayload,
  TokenPayloadSchema,
  UserMeResponse,
  UserMeResponseSchema,
} from "../core/ApiSchemas";
import { logger } from "./Logger";
import {
  deriveAccountPersistentId,
  deriveAccountPublicId,
} from "./identityNamespaces";
import { SELFHOST_FREE_FLARES } from "./selfhost";
// Shared JWKS fetch/cache/rotation (also used by the admin capability
// verifier in ./eduAdminAuth).
import { getKeyByKid } from "./eduJwks";
// Re-exported so existing importers (tests) keep working; the canonical home
// of the cache is ./eduJwks.
export { _resetEduJwksCacheForTests as _resetPocketEduJwksCacheForTests } from "./eduJwks";
// Signature-blind routing check, so an admin capability presented as a
// gameplay credential is rejected explicitly (fail-closed) below.
import { hasAdminCapabilityMarker } from "./eduAdminAuth";

// Re-exported so existing importers keep working; the canonical home of
// these pure functions is ./identityNamespaces (no server dependencies).
export {
  deriveAccountPersistentId,
  deriveAccountPublicId,
  deriveGuestPersistentId,
} from "./identityNamespaces";

const log = logger.child({ comp: "pocketedu-auth" });

// ---------------------------------------------------------------------------
// Pocket Edu account authentication for this self-host.
//
// Pocket Edu remains the system of record for passwords, login codes and
// account permissions. It issues short-lived Ed25519 JWTs; this module only
// *verifies* them against Pocket Edu's public JWKS and derives a stable,
// opaque in-game identity from the verified `sub` claim.
//
// Design notes for auditors:
//
// - The signing private key never leaves Pocket Edu. We only ever fetch the
//   public JWKS from the explicitly configured POCKET_EDU_AUTH_JWKS_URL.
//   Token-supplied `jku`/`x5u` header fields are never read, let alone
//   fetched.
// - Identity is derived deterministically from the verified `sub` claim
//   through three *separate* namespaces, so it is identical in the adapter,
//   the master, every worker, replacement workers, and across restarts:
//     * ACCOUNT_NAMESPACE: the account's authentication identity
//       (persistentId). Only a valid Pocket Edu JWT for that account can
//       ever produce it; it is never exposed to clients.
//     * PUBLIC_NAMESPACE: the account's public profile id (publicId in
//       /users/@me and lobby player lists). Visible to other players, but
//       presenting it as a guest token runs it through the guest namespace
//       and yields a different identity, so it can never authenticate.
//     * GUEST_NAMESPACE: every raw guest UUID is mapped through this
//       namespace before use. A guest presenting an account's raw subject
//       UUID — or its publicId — as their token therefore gets a *guest*
//       identity that is different from the account's, and can never
//       reclaim the account's player seat, lobby ownership, or data.
//   Hashing alone does not separate these; the distinct fixed namespaces
//   do. The namespaces are constants: changing them would reassign every
//   identity, so they must never change.
// - Verification failures are fail-closed: an invalid, expired or
//   unverifiable account token is rejected, never downgraded to a guest.
// - JWKS fetching is bounded (timeout + response size cap), cached with a
//   TTL, de-duplicated while in flight, and refreshed once on unknown `kid`
//   so key rotation works without a restart. A missing/unreachable JWKS
//   only disables *account* authentication; guests keep playing. The
//   fetch/cache machinery is shared with the admin capability verifier in
//   ./eduAdminAuth via ./eduJwks (one cache entry per JWKS URL).
// - Nothing here logs tokens, Authorization headers, cookies or keys.
// ---------------------------------------------------------------------------

const DEFAULT_ISSUER = "https://pocketedu.net";
const DEFAULT_AUDIENCE = "pocketedu-openfront";
const DEFAULT_JWKS_URL = "https://pocketedu.net/.well-known/openfront-jwks.json";

// Maximum token lifetime the contract allows (seconds). Tokens living longer
// are rejected even if their signature is valid.
const MAX_TOKEN_LIFETIME_S = 300;
// Small acceptance window for clock differences between issuer and us.
const CLOCK_TOLERANCE_S = 30;
// Display names are rendered in UI; keep them sane.
const MAX_DISPLAY_NAME_LENGTH = 200;

export function pocketEduIssuer(): string {
  return process.env.POCKET_EDU_AUTH_ISSUER || DEFAULT_ISSUER;
}

export function pocketEduAudience(): string {
  return process.env.POCKET_EDU_AUTH_AUDIENCE || DEFAULT_AUDIENCE;
}

export function pocketEduJwksUrl(): string {
  return process.env.POCKET_EDU_AUTH_JWKS_URL || DEFAULT_JWKS_URL;
}

// ---------------------------------------------------------------------------
// JWKS handling lives in ./eduJwks (shared with the admin capability
// verifier). The per-URL cache, TTL, bounded fetch, in-flight de-dup and
// refresh-on-unknown-kid semantics are unchanged from before the split.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Token verification
// ---------------------------------------------------------------------------

export interface PocketEduIdentity {
  // The account's stable UUID (from the verified `sub` claim), canonical form.
  accountUuid: string;
  // The signed display name (`name` claim). Surfaced in /users/@me; never
  // used to link or identify accounts server-side.
  displayName: string;
  // The in-game authentication identity: derived deterministically from
  // accountUuid through ACCOUNT_NAMESPACE (see deriveAccountPersistentId).
  // Identical in every process and across restarts; never exposed to
  // clients. Only a valid Pocket Edu JWT can produce it.
  persistentId: string;
  // The validated token payload (sub already transformed to UUID string).
  claims: TokenPayload;
}

export type PocketEduVerifyResult =
  | { ok: true; identity: PocketEduIdentity }
  | { ok: false; reason: string };

// (Identity derivation lives in ./identityNamespaces: three fixed,
// disjoint namespaces for guests, account auth identities, and public
// profile ids. See that module for the full rationale.)

function decodePart(part: string): unknown {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

/**
 * Cheap, signature-blind routing check: does this token *claim* to be a
 * Pocket Edu token? Used to decide which verifier must handle it. A `true`
 * answer is not authentication — the token still has to verify.
 */
export function isPocketEduToken(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  try {
    const payload = decodePart(parts[1]) as { iss?: unknown } | null;
    return (
      typeof payload === "object" &&
      payload !== null &&
      payload.iss === pocketEduIssuer()
    );
  } catch {
    return false;
  }
}

export async function verifyPocketEduToken(
  token: string,
): Promise<PocketEduVerifyResult> {
  const fail = (reason: string): PocketEduVerifyResult => ({
    ok: false,
    reason,
  });

  const parts = token.split(".");
  if (parts.length !== 3) return fail("malformed token");

  // Explicit fail-closed routing: an admin capability JWT — or any token
  // carrying an admin marker (the admin audience OR the discrete admin
  // scope) — is never a gameplay credential. Its audience would fail
  // verification below anyway; naming the confusion here keeps the
  // rejection debuggable instead of looking like a generic audience
  // mismatch.
  if (hasAdminCapabilityMarker(token)) {
    log.warn("Pocket Edu admin capability presented as gameplay credential");
    return fail("admin capability presented as gameplay credential");
  }

  let header: unknown;
  try {
    header = decodePart(parts[0]);
  } catch {
    return fail("malformed token header");
  }
  if (typeof header !== "object" || header === null) {
    return fail("malformed token header");
  }
  const { alg, kid } = header as { alg?: unknown; kid?: unknown };
  // The contract fixes the algorithm. Anything else — including `none` —
  // is rejected before any key lookup.
  if (alg !== "EdDSA") return fail("unexpected algorithm");
  if (typeof kid !== "string" || kid.length === 0) {
    return fail("missing key id");
  }
  // NOTE: `jku`/`x5u` header fields, if present, are deliberately ignored:
  // verification keys come only from the configured JWKS URL.

  const jwk = await getKeyByKid(pocketEduJwksUrl(), kid);
  if (!jwk) return fail("unknown signing key");

  let publicKey;
  try {
    publicKey = await importJWK(jwk, "EdDSA");
  } catch {
    return fail("unusable signing key");
  }

  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(token, publicKey, {
      algorithms: ["EdDSA"],
      issuer: pocketEduIssuer(),
      audience: pocketEduAudience(),
      clockTolerance: CLOCK_TOLERANCE_S,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch (e) {
    // Signature, issuer, audience or expiry failure. The message stays
    // generic on purpose: it is returned to callers, never the token.
    const message = e instanceof Error ? e.message : String(e);
    log.warn(`Pocket Edu token failed cryptographic verification: ${message}`);
    return fail("signature/issuer/audience/expiry check failed");
  }

  // Contract claim checks on the *verified* payload.
  if (payload.provider !== "pocketedu") return fail("unexpected provider");
  // No OpenFront admin/mod roles may ever arrive on this path. Pocket Edu
  // issues none; if one ever appears, fail closed rather than honour it.
  if (payload.role !== undefined) return fail("role claim not permitted");
  const name = payload.name;
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name.length > MAX_DISPLAY_NAME_LENGTH
  ) {
    return fail("invalid display name");
  }
  const jti = payload.jti;
  if (typeof jti !== "string" || jti.length === 0) return fail("missing jti");
  const iat = payload.iat;
  const exp = payload.exp;
  if (typeof iat !== "number" || typeof exp !== "number") {
    return fail("missing iat/exp");
  }
  const lifetime = exp - iat;
  if (!(lifetime > 0) || lifetime > MAX_TOKEN_LIFETIME_S) {
    return fail("token lifetime exceeds maximum");
  }

  const claimsResult = TokenPayloadSchema.safeParse(payload);
  if (!claimsResult.success) {
    return fail("payload failed schema validation");
  }
  const claims = claimsResult.data;

  return {
    ok: true,
    identity: {
      accountUuid: claims.sub,
      displayName: name,
      persistentId: deriveAccountPersistentId(claims.sub),
      claims,
    },
  };
}

// ---------------------------------------------------------------------------
// Honest /users/@me profile for verified Pocket Edu accounts.
//
// This self-host has no store, subscriptions, rankings, achievements, clans
// or currency, so the response says exactly that: empty collections, nulls
// and `false` where the schema requires a value. Nothing is fabricated.
//
// Identity separation: the profile exposes the account's *public* id
// (PUBLIC_NAMESPACE derivation) — what other players may see in lobbies.
// The authentication identity (ACCOUNT_NAMESPACE derivation) is never
// exposed here or anywhere client-visible; the raw account UUID is never
// exposed either.
// ---------------------------------------------------------------------------

export function buildPocketEduUserMe(
  identity: PocketEduIdentity,
): UserMeResponse | null {
  const candidate = {
    user: {},
    player: {
      publicId: deriveAccountPublicId(identity.accountUuid),
      adfree: false,
      unlimitedRanked: false,
      canCreatePublicLobbies: false,
      username: identity.displayName,
      achievements: { singleplayerMap: [], player: [] },
      friends: [],
      subscription: null,
      // Self-host: the store is free (see ./selfhost). Every account owns
      // every cosmetic; this is a grant, not a fabricated purchase.
      flares: [...SELFHOST_FREE_FLARES],
    },
  };
  const parsed = UserMeResponseSchema.safeParse(candidate);
  if (!parsed.success) {
    log.warn("Pocket Edu profile failed UserMeResponseSchema validation");
    return null;
  }
  return parsed.data;
}
