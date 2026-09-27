import type { JWK } from "jose";
import { z } from "zod";
import { logger } from "./Logger";

// ---------------------------------------------------------------------------
// Shared JWKS fetching for Pocket Edu issuers.
//
// Both the gameplay account verifier (./pocketEduAuth) and the separate admin
// capability verifier (./eduAdminAuth) resolve Ed25519 keys through this
// module, so the fetch/cache/rotation logic lives in exactly one place.
//
// - One cache entry per JWKS URL: different URLs' keys never mix.
// - Fetching is bounded (timeout + response size cap), cached with a TTL,
//   de-duplicated while in flight, and refreshed once on unknown `kid` so
//   key rotation works without a restart.
// - A missing/unreachable JWKS only disables the authentication that depends
//   on it; the game server keeps working.
// - Token-supplied `jku`/`x5u` header fields are never read, let alone
//   fetched. Nothing here logs response bodies, tokens, or keys.
// ---------------------------------------------------------------------------

const log = logger.child({ comp: "edu-jwks" });

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

const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;
const JWKS_FETCH_TIMEOUT_MS = 5000;
const JWKS_MAX_BYTES = 64 * 1024;

interface JwksState {
  keys: Map<string, JWK>;
  fetchedAt: number;
  inflight: Promise<Map<string, JWK>> | null;
}

const states = new Map<string, JwksState>();

function stateFor(url: string): JwksState {
  let state = states.get(url);
  if (state === undefined) {
    state = { keys: new Map(), fetchedAt: 0, inflight: null };
    states.set(url, state);
  }
  return state;
}

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

async function fetchJwks(url: string): Promise<Map<string, JWK>> {
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
  url: string,
  forceRefresh: boolean,
): Promise<Map<string, JWK> | null> {
  const state = stateFor(url);
  const now = Date.now();
  if (!forceRefresh && now - state.fetchedAt < JWKS_CACHE_TTL_MS) {
    return state.keys;
  }
  if (state.inflight) {
    try {
      return await state.inflight;
    } catch {
      return null;
    }
  }
  const pending = fetchJwks(url)
    .then((keys) => {
      state.keys = keys;
      state.fetchedAt = Date.now();
      state.inflight = null;
      return keys;
    })
    .catch((e: unknown) => {
      state.inflight = null;
      // Never log response bodies or tokens; the URL and the failure class
      // are enough to diagnose a broken issuer configuration.
      log.warn(
        `Pocket Edu JWKS unavailable (${url}): ${e instanceof Error ? e.message : String(e)}`,
      );
      throw e;
    });
  state.inflight = pending;
  try {
    return await pending;
  } catch {
    // Fail closed for the authentication that needs these keys, but never
    // take down the caller: guests and the game server keep working when
    // the issuer is unreachable.
    return null;
  }
}

/**
 * Resolve a `kid` to its JWK from the given JWKS URL, refreshing the document
 * once on a miss (key rotation). Returns null when the JWKS is unreachable
 * or the kid is unknown — callers fail closed.
 */
export async function getKeyByKid(
  jwksUrl: string,
  kid: string,
): Promise<JWK | null> {
  const keys = await getJwksKeys(jwksUrl, false);
  const hit = keys?.get(kid);
  if (hit) return hit;
  // Unknown kid: refresh once in case Pocket Edu rotated keys since our
  // last fetch. A second miss is a genuine rejection, not a retry loop.
  const refreshed = await getJwksKeys(jwksUrl, true);
  return refreshed?.get(kid) ?? null;
}

/** Test-only seam: drop all cached JWKS so tests can start from a clean state. */
export function _resetEduJwksCacheForTests(): void {
  states.clear();
}
