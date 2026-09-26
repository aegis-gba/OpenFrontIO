import { createHmac, randomBytes } from "crypto";
import { importJWK, jwtVerify, type JWK } from "jose";
import { z } from "zod";
import {
  TokenPayload,
  TokenPayloadSchema,
  UserMeResponse,
  UserMeResponseSchema,
} from "../core/ApiSchemas";
import { logger } from "./Logger";

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
// - A verified account's in-game persistent id is NOT the raw account UUID.
//   It is HMAC-SHA256 keyed by a per-process boot secret, formatted as a
//   UUID. A guest who presents an account's subject UUID as a raw guest
//   token therefore gets a *different* identity and can never impersonate
//   the account, take its lobby seat, or read its account data — even for
//   accounts this process has never seen and even across restarts.
//   The boot secret is random per process, never logged, never exposed.
//   Identity is stable for the lifetime of the server process; lobbies and
//   games do not survive a restart either, so nothing outlives it.
// - Verification failures are fail-closed: an invalid, expired or
//   unverifiable account token is rejected, never downgraded to a guest.
// - JWKS fetching is bounded (timeout + response size cap), cached with a
//   TTL, de-duplicated while in flight, and refreshed once on unknown `kid`
//   so key rotation works without a restart. A missing/unreachable JWKS
//   only disables *account* authentication; guests keep playing.
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

const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;
const JWKS_FETCH_TIMEOUT_MS = 5000;
const JWKS_MAX_BYTES = 64 * 1024;

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
// JWKS handling
// ---------------------------------------------------------------------------

const PocketEduJwksSchema = z.object({
  keys: z
    .array(
      z.object({
        kty: z.literal("OKP"),
        crv: z.literal("Ed25519"),
        x: z.string().min(1),
        kid: z.string().min(1),
        // `alg` is optional in JWKS documents; when present it must be EdDSA.
        alg: z.literal("EdDSA").optional(),
      }),
    )
    .min(1),
});

interface JwksState {
  keys: Map<string, JWK>;
  fetchedAt: number;
  inflight: Promise<Map<string, JWK>> | null;
}

const jwksState: JwksState = { keys: new Map(), fetchedAt: 0, inflight: null };

async function readBoundedBody(
  response: Response,
  maxBytes: number,
): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    // Fallback: no streaming body (e.g. mocked Response). Cap after the fact.
    const text = await response.text();
    if (text.length > maxBytes) throw new Error("JWKS response too large");
    return text;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("JWKS response too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function fetchJwks(): Promise<Map<string, JWK>> {
  const url = pocketEduJwksUrl();
  let response: Response;
  try {
    response = await fetch(url, {
      signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS),
      headers: { accept: "application/json" },
    });
  } catch (e) {
    throw new Error(
      `JWKS fetch failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (!response.ok) {
    throw new Error(`JWKS fetch failed: HTTP ${response.status}`);
  }
  const text = await readBoundedBody(response, JWKS_MAX_BYTES);
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error("JWKS response is not valid JSON");
  }
  const parsed = PocketEduJwksSchema.safeParse(json);
  if (!parsed.success) {
    throw new Error("JWKS response failed schema validation");
  }
  const keys = new Map<string, JWK>();
  for (const k of parsed.data.keys) {
    // First key wins on duplicate kid: rotation publishes the new key under
    // a new kid, so duplicates are a misconfiguration, not a rotation.
    if (!keys.has(k.kid)) keys.set(k.kid, k as JWK);
  }
  return keys;
}

async function getJwksKeys(
  forceRefresh: boolean,
): Promise<Map<string, JWK> | null> {
  const now = Date.now();
  if (!forceRefresh && now - jwksState.fetchedAt < JWKS_CACHE_TTL_MS) {
    return jwksState.keys;
  }
  if (jwksState.inflight) {
    try {
      return await jwksState.inflight;
    } catch {
      return null;
    }
  }
  const pending = fetchJwks()
    .then((keys) => {
      jwksState.keys = keys;
      jwksState.fetchedAt = Date.now();
      jwksState.inflight = null;
      return keys;
    })
    .catch((e: unknown) => {
      jwksState.inflight = null;
      // Never log response bodies or tokens; the URL and the failure class
      // are enough to diagnose a broken issuer configuration.
      log.warn(
        `Pocket Edu JWKS unavailable (${pocketEduJwksUrl()}): ${e instanceof Error ? e.message : String(e)}`,
      );
      throw e;
    });
  jwksState.inflight = pending;
  try {
    return await pending;
  } catch {
    // Fail closed for account auth, but never take down the caller: guests
    // and the game server keep working when the issuer is unreachable.
    return null;
  }
}

async function getKeyByKid(kid: string): Promise<JWK | null> {
  const keys = await getJwksKeys(false);
  const hit = keys?.get(kid);
  if (hit) return hit;
  // Unknown kid: refresh once in case Pocket Edu rotated keys since our
  // last fetch. A second miss is a genuine rejection, not a retry loop.
  const refreshed = await getJwksKeys(true);
  return refreshed?.get(kid) ?? null;
}

/** Test-only seam: drop the cached JWKS so tests can start from a clean state. */
export function _resetPocketEduJwksCacheForTests(): void {
  jwksState.keys = new Map();
  jwksState.fetchedAt = 0;
  jwksState.inflight = null;
}

// ---------------------------------------------------------------------------
// Token verification
// ---------------------------------------------------------------------------

export interface PocketEduIdentity {
  // The account's stable UUID (from the verified `sub` claim), canonical form.
  accountUuid: string;
  // The signed display name (`name` claim). Surfaced in /users/@me; never
  // used to link or identify accounts server-side.
  displayName: string;
  // The in-game identity: HMAC-derived from accountUuid, UUID-shaped,
  // stable for the process lifetime, unguessable without the boot secret.
  persistentId: string;
  // The validated token payload (sub already transformed to UUID string).
  claims: TokenPayload;
}

export type PocketEduVerifyResult =
  | { ok: true; identity: PocketEduIdentity }
  | { ok: false; reason: string };

// Per-process boot secret for account identity derivation. Random every
// boot; never persisted, never logged, never sent anywhere.
const bootSecret = randomBytes(32);

/**
 * Derive the in-game persistent id for a verified Pocket Edu account.
 * UUID-shaped (so existing UUID-typed fields keep validating), deterministic
 * per boot, and unforgeable: without the boot secret nobody can compute the
 * id for a given account UUID, so a guest presenting a raw account UUID as
 * their guest token can never collide with the account's identity.
 */
export function deriveAccountPersistentId(accountUuid: string): string {
  const digest = createHmac("sha256", bootSecret)
    .update(`pocketedu:v1:${accountUuid}`, "utf8")
    .digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
  const hex = bytes.toString("hex");
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}` +
    `-${hex.slice(16, 20)}-${hex.slice(20)}`
  );
}

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

  const jwk = await getKeyByKid(kid);
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
// The stable identity is the derived persistent id (opaque, per-boot); the
// raw account UUID is never exposed here.
// ---------------------------------------------------------------------------

export function buildPocketEduUserMe(
  identity: PocketEduIdentity,
): UserMeResponse | null {
  const candidate = {
    user: {},
    player: {
      publicId: identity.persistentId,
      adfree: false,
      unlimitedRanked: false,
      canCreatePublicLobbies: false,
      username: identity.displayName,
      achievements: { singleplayerMap: [], player: [] },
      friends: [],
      subscription: null,
    },
  };
  const parsed = UserMeResponseSchema.safeParse(candidate);
  if (!parsed.success) {
    log.warn("Pocket Edu profile failed UserMeResponseSchema validation");
    return null;
  }
  return parsed.data;
}
