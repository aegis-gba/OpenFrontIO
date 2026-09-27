import { base64url, importJWK, jwtVerify } from "jose";
import { logger } from "./Logger";
import { getKeyByKid } from "./eduJwks";
import { deriveAccountPersistentId } from "./identityNamespaces";

// ---------------------------------------------------------------------------
// Pocket Edu *admin capability* authentication for this self-host.
//
// This is a SEPARATE credential from the gameplay account JWT verified in
// ./pocketEduAuth: a short-lived (<= 60s) Ed25519 JWT that authorizes a
// Pocket Edu admin to run moderation commands against this server's games.
// Pocket Edu remains the system of record — it signs these tokens, and this
// module only *verifies* them against Pocket Edu's public JWKS.
//
// The two token classes are strictly separated in both directions:
//  - An admin capability presented as a gameplay credential is rejected by
//    verifyPocketEduToken (explicit check, fail-closed).
//  - A gameplay token presented as an admin capability fails here (wrong
//    audience, no admin scope).
// Admin rights are derived ONLY from a verified admin JWT's `sub` claim,
// mapped through deriveAccountPersistentId (the same ACCOUNT namespace the
// gameplay path uses). They are never inferred from `role`, display names,
// public profile ids, lobby-creator status, or any client-claimed field.
//
// Design notes for auditors:
//  - The signing private key never leaves Pocket Edu. Keys come only from
//    the configured POCKET_EDU_ADMIN_JWKS_URL (default
//    https://pocketedu.net/.well-known/openfront-jwks.json). Token-supplied
//    `jku`/`x5u` header fields are never read, let alone fetched.
//  - Verification failures are fail-closed with a typed reason; callers map
//    to HTTP 401 with a generic message. Specific reasons are logged
//    server-side only — never token material.
// ---------------------------------------------------------------------------

const log = logger.child({ comp: "edu-admin-auth" });

const DEFAULT_ISSUER = "https://pocketedu.net";
const DEFAULT_AUDIENCE = "pocketedu-openfront-admin";
const DEFAULT_JWKS_URL =
  "https://pocketedu.net/.well-known/openfront-jwks.json";

// Maximum lifetime of an admin capability (seconds). The short window bounds
// the damage of a leaked token.
const MAX_ADMIN_TOKEN_LIFETIME_S = 60;
// Acceptance window for clock differences between issuer and us, applied to
// `iat` ("not issued in the future"). `exp` must be strictly in the future.
const ADMIN_CLOCK_TOLERANCE_S = 5;

const ADMIN_PROVIDER = "pocketedu";
const ADMIN_SCOPE = "openfront:admin";

export function eduAdminIssuer(): string {
  return process.env.POCKET_EDU_AUTH_ISSUER || DEFAULT_ISSUER;
}

export function eduAdminAudience(): string {
  return process.env.POCKET_EDU_ADMIN_AUDIENCE || DEFAULT_AUDIENCE;
}

export function eduAdminJwksUrl(): string {
  return process.env.POCKET_EDU_ADMIN_JWKS_URL || DEFAULT_JWKS_URL;
}

// ---------------------------------------------------------------------------
// Token verification
// ---------------------------------------------------------------------------

export interface EduAdminIdentity {
  // The account's stable UUID (from the verified `sub` claim), canonical form.
  accountUuid: string;
  // The in-game authentication identity: deriveAccountPersistentId(sub), the
  // same ACCOUNT_NAMESPACE derivation the gameplay path uses, so the admin
  // actor is the same identity the account would have in-game.
  persistentId: string;
}

export type EduAdminVerifyResult =
  | { ok: true; identity: EduAdminIdentity }
  | { ok: false; reason: string };

function decodePart(part: string): unknown {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

function hasAdminScope(scope: unknown): boolean {
  return typeof scope === "string" && scope.split(/\s+/).includes(ADMIN_SCOPE);
}

function hasAdminAudience(aud: unknown, expectedAud: string): boolean {
  // Exact audience match. If aud is an array it must contain exactly that
  // value — a single-element array equal to the expected audience.
  return (
    aud === expectedAud ||
    (Array.isArray(aud) && aud.length === 1 && aud[0] === expectedAud)
  );
}

/**
 * Cheap, signature-blind routing check: does this token *claim* to be a
 * Pocket Edu admin capability? Used by the gameplay verifier to reject an
 * admin token presented as a gameplay credential with a clear reason. A
 * `true` answer is not authentication — the token still has to verify.
 */
export function isAdminCapabilityToken(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  try {
    const payload = decodePart(parts[1]) as Record<string, unknown> | null;
    if (typeof payload !== "object" || payload === null) return false;
    if (payload.iss !== eduAdminIssuer()) return false;
    if (payload.provider !== ADMIN_PROVIDER) return false;
    if (!hasAdminAudience(payload.aud, eduAdminAudience())) return false;
    return hasAdminScope(payload.scope);
  } catch {
    return false;
  }
}

/**
 * Confusion check for the gameplay verifier: does this token carry ANY admin
 * marker — the admin audience OR the discrete `openfront:admin` scope —
 * from our issuer? Deliberately looser than isAdminCapabilityToken (OR
 * instead of AND): any admin marker on a gameplay credential is a routing
 * confusion and must be rejected with a specific reason, even when the token
 * is not a complete admin capability. (A token with the admin audience
 * would fail the gameplay audience check anyway; naming the confusion keeps
 * the rejection debuggable instead of looking like a generic audience
 * mismatch.) Blind like isAdminCapabilityToken: not authentication.
 */
export function hasAdminCapabilityMarker(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  try {
    const payload = decodePart(parts[1]) as Record<string, unknown> | null;
    if (typeof payload !== "object" || payload === null) return false;
    if (payload.iss !== eduAdminIssuer()) return false;
    if (payload.provider !== ADMIN_PROVIDER) return false;
    return (
      hasAdminAudience(payload.aud, eduAdminAudience()) ||
      hasAdminScope(payload.scope)
    );
  } catch {
    return false;
  }
}

/**
 * Validate the `sub` claim: it must be the same opaque account subject the
 * gameplay path uses — a base64url-encoded 16-byte UUID. Returns the
 * canonical UUID string, or null when the shape is wrong.
 */
function subToAccountUuid(sub: string): string | null {
  let bytes: Uint8Array;
  try {
    bytes = base64url.decode(sub);
  } catch {
    return null;
  }
  if (bytes.length !== 16) return null;
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}` +
    `-${hex.slice(16, 20)}-${hex.slice(20)}`
  );
}

export async function verifyEduAdminToken(
  token: string,
): Promise<EduAdminVerifyResult> {
  // Reasons are logged server-side only; callers return a generic 401.
  const fail = (reason: string): EduAdminVerifyResult => {
    log.warn(`Edu admin token rejected: ${reason}`);
    return { ok: false, reason };
  };

  const parts = token.split(".");
  if (parts.length !== 3) return fail("malformed token");

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

  // Explicit early guard: a gameplay credential (or anything else that does
  // not even claim the admin audience + scope) is never an admin capability.
  // The checks on the verified payload below would reject it anyway; naming
  // it here keeps the rejection debuggable. Fail-closed: rejection only.
  let claimed: unknown;
  try {
    claimed = decodePart(parts[1]);
  } catch {
    return fail("malformed token payload");
  }
  if (typeof claimed !== "object" || claimed === null) {
    return fail("malformed token payload");
  }
  const claimedPayload = claimed as Record<string, unknown>;
  if (!hasAdminAudience(claimedPayload.aud, eduAdminAudience())) {
    return fail("not an admin capability token (audience)");
  }
  if (!hasAdminScope(claimedPayload.scope)) {
    return fail("not an admin capability token (scope)");
  }

  const jwk = await getKeyByKid(eduAdminJwksUrl(), kid);
  if (!jwk) return fail("unknown signing key");

  let publicKey;
  try {
    publicKey = await importJWK(jwk, "EdDSA");
  } catch {
    return fail("unusable signing key");
  }

  let payload: Record<string, unknown>;
  try {
    // Signature + issuer + expiry (5s tolerance). Audience is checked
    // strictly by hand below rather than via jose's looser semantics.
    const verified = await jwtVerify(token, publicKey, {
      algorithms: ["EdDSA"],
      issuer: eduAdminIssuer(),
      clockTolerance: ADMIN_CLOCK_TOLERANCE_S,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    log.warn(`Edu admin token failed cryptographic verification: ${message}`);
    return fail("signature/issuer/expiry check failed");
  }

  // Contract claim checks on the *verified* payload. Every one is strict:
  // a capability is all-or-nothing.
  if (payload.provider !== ADMIN_PROVIDER) return fail("unexpected provider");
  if (!hasAdminAudience(payload.aud, eduAdminAudience())) {
    return fail("unexpected audience");
  }
  if (!hasAdminScope(payload.scope)) return fail("missing admin scope");
  const sub = payload.sub;
  if (typeof sub !== "string" || sub.length === 0) {
    return fail("missing sub");
  }
  const accountUuid = subToAccountUuid(sub);
  if (accountUuid === null) return fail("invalid sub");
  const iat = payload.iat;
  const exp = payload.exp;
  if (
    typeof iat !== "number" ||
    !Number.isFinite(iat) ||
    typeof exp !== "number" ||
    !Number.isFinite(exp)
  ) {
    return fail("missing iat/exp");
  }
  const now = Math.floor(Date.now() / 1000);
  if (!(iat > 0)) return fail("invalid iat");
  // `exp` must be strictly in the future; `iat` may not be in the future
  // beyond a small clock tolerance.
  if (exp <= now) return fail("token expired");
  if (iat > now + ADMIN_CLOCK_TOLERANCE_S) {
    return fail("token issued in the future");
  }
  const lifetime = exp - iat;
  if (!(lifetime > 0) || lifetime > MAX_ADMIN_TOKEN_LIFETIME_S) {
    return fail("token lifetime exceeds maximum");
  }

  // The actor identity is derived ONLY from the verified `sub`, through the
  // same ACCOUNT namespace the gameplay path uses. Nothing client-supplied
  // beyond the verified claims influences it.
  return {
    ok: true,
    identity: {
      accountUuid,
      persistentId: deriveAccountPersistentId(accountUuid),
    },
  };
}
