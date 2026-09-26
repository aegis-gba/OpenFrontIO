/**
 * @vitest-environment node
 */
import { randomUUID } from "crypto";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UserMeResponseSchema } from "../../src/core/ApiSchemas";
import { uuidToBase64url } from "../../src/core/Base64";
import {
  _resetPocketEduJwksCacheForTests,
  buildPocketEduUserMe,
  deriveAccountPersistentId,
  deriveAccountPublicId,
  deriveGuestPersistentId,
  isPocketEduToken,
  verifyPocketEduToken,
} from "../../src/server/pocketEduAuth";
import { verifyClientToken } from "../../src/server/jwt";
import { SELFHOST_FREE_FLARES } from "../../src/server/selfhost";

// ---------------------------------------------------------------------------
// Pocket Edu authentication tests.
//
// A fresh Ed25519 keypair stands in for Pocket Edu's issuer; the real
// private key is never involved. The JWKS endpoint is stubbed at the fetch
// layer so no network is touched.
// ---------------------------------------------------------------------------

const ISSUER = "https://pocketedu.test";
const AUDIENCE = "pocketedu-openfront-test";
const JWKS_URL = "https://pocketedu.test/.well-known/openfront-jwks.json";
const KID = "test-key-1";
const ACCOUNT_UUID = "123e4567-e89b-12d3-a456-426614174000";
const OTHER_UUID = "223e4567-e89b-12d3-a456-426614174001";

let privateKey: CryptoKey;
let jwk: JWK;

function stubJwks(keys: JWK[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url === JWKS_URL) {
        return new Response(JSON.stringify({ keys }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch of ${url}`);
    }),
  );
}

interface TokenOpts {
  key?: CryptoKey;
  kid?: string;
  alg?: string;
  iss?: unknown;
  aud?: unknown;
  sub?: unknown;
  provider?: unknown;
  name?: unknown;
  role?: unknown;
  jti?: unknown;
  iat?: number;
  exp?: number;
  extraHeader?: Record<string, unknown>;
  omitIat?: boolean;
}

async function makeToken(opts: TokenOpts = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: opts.iss ?? ISSUER,
    aud: opts.aud ?? AUDIENCE,
    sub: opts.sub ?? uuidToBase64url(ACCOUNT_UUID),
    provider: opts.provider ?? "pocketedu",
    name: opts.name ?? "Test Player",
    jti: opts.jti ?? randomUUID(),
    iat: opts.iat ?? now,
    exp: opts.exp ?? now + 120,
  };
  if (opts.omitIat) delete payload.iat;
  if (opts.role !== undefined) payload.role = opts.role;
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: opts.alg ?? "EdDSA",
      kid: opts.kid ?? KID,
      ...(opts.extraHeader ?? {}),
    })
    .sign(opts.key ?? privateKey);
}

beforeEach(async () => {
  vi.stubEnv("POCKET_EDU_AUTH_ISSUER", ISSUER);
  vi.stubEnv("POCKET_EDU_AUTH_AUDIENCE", AUDIENCE);
  vi.stubEnv("POCKET_EDU_AUTH_JWKS_URL", JWKS_URL);
  _resetPocketEduJwksCacheForTests();
  if (!privateKey) {
    const pair = await generateKeyPair("EdDSA");
    privateKey = pair.privateKey;
    jwk = await exportJWK(pair.publicKey);
    jwk.kid = KID;
    jwk.alg = "EdDSA";
  }
  stubJwks([jwk]);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("verifyPocketEduToken", () => {
  it("accepts a valid token and derives a stable, opaque identity", async () => {
    const first = await verifyPocketEduToken(await makeToken());
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const id1 = first.identity;
    expect(id1.accountUuid).toBe(ACCOUNT_UUID);
    expect(id1.displayName).toBe("Test Player");
    expect(id1.claims.provider).toBe("pocketedu");
    // UUIDv5-shaped but not the account UUID itself.
    expect(id1.persistentId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(id1.persistentId).not.toBe(ACCOUNT_UUID);

    // A second, separately-issued token for the same account keeps the
    // same identity (stable across tokens/sessions).
    const second = await verifyPocketEduToken(await makeToken());
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.identity.persistentId).toBe(id1.persistentId);

    // A different account is a different identity.
    const other = await verifyPocketEduToken(
      await makeToken({ sub: uuidToBase64url(OTHER_UUID) }),
    );
    expect(other.ok).toBe(true);
    if (!other.ok) return;
    expect(other.identity.persistentId).not.toBe(id1.persistentId);
  });

  it("rejects a tampered token", async () => {
    const token = await makeToken();
    const parts = token.split(".");
    const sig = parts[2];
    // Flip the FIRST character, not the last: the final base64url char of a
    // 64-byte Ed25519 signature carries only pad bits, so flipping it can
    // decode to the identical signature and pass verification by luck.
    const flipped = (sig.startsWith("A") ? "B" : "A") + sig.slice(1);
    const result = await verifyPocketEduToken(
      `${parts[0]}.${parts[1]}.${flipped}`,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyPocketEduToken(
      await makeToken({ iat: now - 400, exp: now - 100 }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a wrong issuer (and isPocketEduToken does not route it)", async () => {
    const token = await makeToken({ iss: "https://evil.test" });
    expect(isPocketEduToken(token)).toBe(false);
    // Routed by iss claim, not by shape: a token claiming our issuer is
    // required here; without the claim the verifier must not be consulted.
    const result = await verifyPocketEduToken(token);
    expect(result.ok).toBe(false);
  });

  it("rejects a wrong audience", async () => {
    const result = await verifyPocketEduToken(
      await makeToken({ aud: "someone-else" }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects an unknown kid", async () => {
    const other = await generateKeyPair("EdDSA");
    const result = await verifyPocketEduToken(
      await makeToken({ key: other.privateKey, kid: "no-such-key" }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects an unsigned token", async () => {
    const header = Buffer.from(
      JSON.stringify({ alg: "none", kid: KID }),
    ).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(
      JSON.stringify({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: uuidToBase64url(ACCOUNT_UUID),
        provider: "pocketedu",
        name: "Test Player",
        jti: randomUUID(),
        iat: now,
        exp: now + 120,
      }),
    ).toString("base64url");
    const result = await verifyPocketEduToken(`${header}.${payload}.`);
    expect(result.ok).toBe(false);
  });

  it("rejects a token living longer than 300 seconds", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyPocketEduToken(
      await makeToken({ iat: now, exp: now + 301 }),
    );
    expect(result.ok).toBe(false);
  });

  it("accepts a token at exactly 300 seconds", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyPocketEduToken(
      await makeToken({ iat: now, exp: now + 300 }),
    );
    expect(result.ok).toBe(true);
  });

  it("rejects any role claim", async () => {
    const result = await verifyPocketEduToken(
      await makeToken({ role: "admin" }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a wrong provider claim", async () => {
    const result = await verifyPocketEduToken(
      await makeToken({ provider: "steam" }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a missing display name", async () => {
    const result = await verifyPocketEduToken(await makeToken({ name: "" }));
    expect(result.ok).toBe(false);
  });

  it("rejects a missing jti", async () => {
    const result = await verifyPocketEduToken(await makeToken({ jti: "" }));
    expect(result.ok).toBe(false);
  });

  it("rejects a missing iat", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyPocketEduToken(
      await makeToken({ exp: now + 120, omitIat: true }),
    );
    expect(result.ok).toBe(false);
  });

  it("fails closed when the JWKS endpoint is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    const result = await verifyPocketEduToken(await makeToken());
    expect(result.ok).toBe(false);
  });

  it("picks up rotated keys via refresh on unknown kid", async () => {
    const rotated = await generateKeyPair("EdDSA");
    const rotatedJwk = await exportJWK(rotated.publicKey);
    rotatedJwk.kid = "rotated-key-2";
    rotatedJwk.alg = "EdDSA";
    const token = await makeToken({
      key: rotated.privateKey,
      kid: "rotated-key-2",
    });

    // First fetch serves only the old key; the verifier must refresh once
    // on the unknown kid and then verify against the rotated key.
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        calls++;
        const keys = calls === 1 ? [jwk] : [jwk, rotatedJwk];
        return new Response(JSON.stringify({ keys }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }),
    );
    const result = await verifyPocketEduToken(token);
    expect(result.ok).toBe(true);
    expect(calls).toBe(2);
  });

  it("ignores token-supplied jku/x5u and still verifies via configured JWKS", async () => {
    const token = await makeToken({
      extraHeader: { jku: "https://evil.test/keys.json" },
    });
    const result = await verifyPocketEduToken(token);
    expect(result.ok).toBe(true);
  });
});

describe("buildPocketEduUserMe", () => {
  it("produces a schema-valid, honest profile with the self-host free grant", async () => {
    const verified = await verifyPocketEduToken(await makeToken());
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;
    const profile = buildPocketEduUserMe(verified.identity);
    expect(profile).not.toBeNull();
    expect(UserMeResponseSchema.safeParse(profile).success).toBe(true);
    // The profile exposes the account's *public* id, which is separate
    // from its authentication identity (persistentId).
    expect(profile!.player.publicId).toBe(deriveAccountPublicId(ACCOUNT_UUID));
    expect(profile!.player.publicId).not.toBe(verified.identity.persistentId);
    expect(profile!.player.username).toBe("Test Player");
    expect(profile!.player.adfree).toBe(false);
    expect(profile!.player.unlimitedRanked).toBe(false);
    expect(profile!.player.canCreatePublicLobbies).toBe(false);
    expect(profile!.player.friends).toEqual([]);
    expect(profile!.player.subscription).toBeNull();
    // Self-host: the store is free, so every account owns every cosmetic.
    // The flares below are the actual self-host grant (see src/server/selfhost),
    // not a fabricated purchase; no currency, rankings, clans or
    // achievements are invented.
    expect(profile!.player.flares).toEqual([...SELFHOST_FREE_FLARES]);
    const rawPlayer = profile!.player as unknown as Record<string, unknown>;
    expect(rawPlayer.leaderboard).toBeUndefined();
    expect(rawPlayer.clan).toBeUndefined();
  });
});

describe("verifyClientToken routing", () => {
  it("authenticates a valid Pocket Edu token as an account", async () => {
    const result = await verifyClientToken(await makeToken());
    expect(result.type).toBe("success");
    if (result.type !== "success") return;
    expect(result.provider).toBe("pocketedu");
    expect(result.displayName).toBe("Test Player");
    expect(result.claims?.provider).toBe("pocketedu");
    expect(result.persistentId).toBe(
      deriveAccountPersistentId(ACCOUNT_UUID),
    );
  });

  it("rejects an invalid Pocket Edu-claimed token instead of downgrading to guest", async () => {
    const token = await makeToken();
    const tampered = token.slice(0, -2) + "xx";
    const result = await verifyClientToken(tampered);
    expect(result.type).toBe("error");
  });

  it("does not let a guest UUID impersonate a Pocket Edu account", async () => {
    // Under dev (the vitest default) a raw UUID is accepted as a guest,
    // but the raw token is mapped through the guest namespace first.
    const guest = await verifyClientToken(ACCOUNT_UUID);
    expect(guest.type).toBe("success");
    if (guest.type !== "success") return;
    expect(guest.provider).toBe("guest");
    expect(guest.persistentId).toBe(deriveGuestPersistentId(ACCOUNT_UUID));
    // The account's in-game identity lives in a different namespace, so
    // the guest and the account are different players.
    expect(guest.persistentId).not.toBe(deriveAccountPersistentId(ACCOUNT_UUID));
  });
});

describe("identity namespaces (regression)", () => {
  // Fixed vectors pin the derivation permanently: the mapping is a pure
  // function of the namespace constants, so one signed account gets the
  // same identity in the adapter, the master, every worker, replacement
  // workers, and across restarts. If these vectors ever change, every
  // identity reassigns — that must be a deliberate migration, never an
  // accident.
  it("matches fixed cross-process test vectors", () => {
    expect(deriveAccountPersistentId(ACCOUNT_UUID)).toBe(
      "a2dcd68b-9384-5d39-9efa-198e7d5eea37",
    );
    expect(deriveAccountPublicId(ACCOUNT_UUID)).toBe(
      "5faf33e7-0919-59b8-a99b-05c41e8113b5",
    );
    expect(deriveGuestPersistentId(ACCOUNT_UUID)).toBe(
      "589f4cf5-b4c9-5086-bd78-366ed6b3ab25",
    );
  });

  it("keeps the three namespaces disjoint for the same input", () => {
    const account = deriveAccountPersistentId(ACCOUNT_UUID);
    const pub = deriveAccountPublicId(ACCOUNT_UUID);
    const guest = deriveGuestPersistentId(ACCOUNT_UUID);
    // account != public != guest != raw input, all four distinct.
    expect(new Set([account, pub, guest, ACCOUNT_UUID]).size).toBe(4);
    // Input case is normalized.
    expect(deriveAccountPersistentId(ACCOUNT_UUID.toUpperCase())).toBe(account);
    expect(deriveGuestPersistentId(ACCOUNT_UUID.toUpperCase())).toBe(guest);
    expect(deriveAccountPublicId(ACCOUNT_UUID.toUpperCase())).toBe(pub);
  });

  it("derives a stable guest identity for the same raw token", async () => {
    const raw = randomUUID();
    const first = await verifyClientToken(raw);
    const second = await verifyClientToken(raw);
    expect(first.type).toBe("success");
    expect(second.type).toBe("success");
    if (first.type !== "success" || second.type !== "success") return;
    expect(first.provider).toBe("guest");
    expect(first.persistentId).toBe(deriveGuestPersistentId(raw));
    expect(second.persistentId).toBe(first.persistentId);
  });

  it("does not let a guest presenting an account's publicId become the account", async () => {
    const publicId = deriveAccountPublicId(ACCOUNT_UUID);
    const guest = await verifyClientToken(publicId);
    expect(guest.type).toBe("success");
    if (guest.type !== "success") return;
    expect(guest.provider).toBe("guest");
    // Mapped through the guest namespace: a different identity that is
    // neither the account's auth identity nor usable as the publicId.
    expect(guest.persistentId).toBe(deriveGuestPersistentId(publicId));
    expect(guest.persistentId).not.toBe(deriveAccountPersistentId(ACCOUNT_UUID));
    expect(guest.persistentId).not.toBe(publicId);
  });

  it("gives a reconnecting account the same identity as its first session", async () => {
    // Fresh tokens (new jti/iat/exp) for the same account — e.g. a page
    // refresh after the 300s token expired — must map to the same
    // persistentId so rejoin and lobby-creator checks keep working.
    const first = await verifyClientToken(await makeToken());
    const second = await verifyClientToken(await makeToken());
    expect(first.type).toBe("success");
    expect(second.type).toBe("success");
    if (first.type !== "success" || second.type !== "success") return;
    expect(first.persistentId).toBe(second.persistentId);
    expect(first.persistentId).toBe(deriveAccountPersistentId(ACCOUNT_UUID));
  });

  it("keeps different accounts distinct in every namespace", async () => {
    const a = await verifyPocketEduToken(await makeToken());
    const b = await verifyPocketEduToken(
      await makeToken({ sub: uuidToBase64url(OTHER_UUID) }),
    );
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.identity.persistentId).not.toBe(b.identity.persistentId);
    expect(deriveAccountPublicId(ACCOUNT_UUID)).not.toBe(
      deriveAccountPublicId(OTHER_UUID),
    );
  });
});
