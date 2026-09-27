/**
 * @vitest-environment node
 */
import { randomUUID } from "crypto";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { uuidToBase64url } from "../../src/core/Base64";
import {
  eduAdminAudience,
  eduAdminIssuer,
  hasAdminCapabilityMarker,
  isAdminCapabilityToken,
  verifyEduAdminToken,
} from "../../src/server/eduAdminAuth";
import { deriveAccountPersistentId } from "../../src/server/identityNamespaces";
import {
  _resetPocketEduJwksCacheForTests,
  verifyPocketEduToken,
} from "../../src/server/pocketEduAuth";

// ---------------------------------------------------------------------------
// Pocket Edu admin capability tests.
//
// A fresh Ed25519 keypair stands in for Pocket Edu's issuer; the real
// private key is never involved. The JWKS endpoint is stubbed at the fetch
// layer so no network is touched. Both the gameplay and admin verifiers are
// pointed at the same stubbed JWKS: key identity is shared on purpose, so
// the cross-rejection tests prove the separation is enforced by claims
// (audience / scope), not by keys.
// ---------------------------------------------------------------------------

const ISSUER = "https://pocketedu.test";
const GAMEPLAY_AUDIENCE = "pocketedu-openfront-test";
const ADMIN_AUDIENCE = "pocketedu-openfront-admin-test";
const JWKS_URL = "https://pocketedu.test/.well-known/openfront-jwks.json";
const KID = "test-admin-key-1";
const ACCOUNT_UUID = "123e4567-e89b-12d3-a456-426614174000";

let privateKey: CryptoKey;
let otherPrivateKey: CryptoKey;
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

interface AdminTokenOpts {
  key?: CryptoKey;
  kid?: string | null;
  alg?: string;
  iss?: unknown;
  aud?: unknown;
  sub?: unknown;
  provider?: unknown;
  scope?: unknown;
  iat?: number;
  exp?: number;
  omitIat?: boolean;
  omitExp?: boolean;
  extraHeader?: Record<string, unknown>;
  extraClaims?: Record<string, unknown>;
}

async function makeAdminToken(opts: AdminTokenOpts = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: opts.iss ?? ISSUER,
    aud: opts.aud ?? ADMIN_AUDIENCE,
    sub: opts.sub ?? uuidToBase64url(ACCOUNT_UUID),
    provider: opts.provider ?? "pocketedu",
    scope: opts.scope ?? "openfront:admin",
    ...(opts.extraClaims ?? {}),
  };
  if (!opts.omitIat) payload.iat = opts.iat ?? now;
  if (!opts.omitExp) payload.exp = opts.exp ?? now + 30;
  const header: { alg: string } & Record<string, unknown> = {
    alg: opts.alg ?? "EdDSA",
    ...(opts.kid !== null ? { kid: opts.kid ?? KID } : {}),
    ...(opts.extraHeader ?? {}),
  };
  return new SignJWT(payload)
    .setProtectedHeader(header)
    .sign(opts.key ?? privateKey);
}

/** A compact JWS assembled by hand, for algorithm-confusion cases jose won't sign. */
function handcraftedToken(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64(header)}.${b64(payload)}.bogus-signature`;
}

function adminPayload(
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: ADMIN_AUDIENCE,
    sub: uuidToBase64url(ACCOUNT_UUID),
    provider: "pocketedu",
    scope: "openfront:admin",
    iat: now,
    exp: now + 30,
    ...over,
  };
}

beforeEach(async () => {
  vi.stubEnv("POCKET_EDU_AUTH_ISSUER", ISSUER);
  vi.stubEnv("POCKET_EDU_AUTH_AUDIENCE", GAMEPLAY_AUDIENCE);
  vi.stubEnv("POCKET_EDU_AUTH_JWKS_URL", JWKS_URL);
  vi.stubEnv("POCKET_EDU_ADMIN_AUDIENCE", ADMIN_AUDIENCE);
  vi.stubEnv("POCKET_EDU_ADMIN_JWKS_URL", JWKS_URL);
  _resetPocketEduJwksCacheForTests();
  if (!privateKey) {
    const pair = await generateKeyPair("EdDSA");
    privateKey = pair.privateKey;
    jwk = await exportJWK(pair.publicKey);
    jwk.kid = KID;
    jwk.alg = "EdDSA";
    const other = await generateKeyPair("EdDSA");
    otherPrivateKey = other.privateKey;
  }
  stubJwks([jwk]);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("verifyEduAdminToken", () => {
  it("accepts a valid admin token and derives the account identity", async () => {
    const result = await verifyEduAdminToken(await makeAdminToken());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.identity.accountUuid).toBe(ACCOUNT_UUID);
    expect(result.identity.persistentId).toBe(
      deriveAccountPersistentId(ACCOUNT_UUID),
    );
  });

  it("accepts the admin scope among other space-separated scopes", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ scope: "read openfront:admin write" }),
    );
    expect(result.ok).toBe(true);
  });

  it("accepts a single-element audience array with the admin audience", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ aud: [ADMIN_AUDIENCE] }),
    );
    expect(result.ok).toBe(true);
  });

  it("accepts the maximum 60s lifetime", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyEduAdminToken(
      await makeAdminToken({ iat: now, exp: now + 60 }),
    );
    expect(result.ok).toBe(true);
  });

  it("rejects a malformed token", async () => {
    expect((await verifyEduAdminToken("not-a-token")).ok).toBe(false);
    expect((await verifyEduAdminToken("a.b")).ok).toBe(false);
  });

  it("rejects alg none", async () => {
    const token = handcraftedToken({ alg: "none", kid: KID }, adminPayload());
    const result = await verifyEduAdminToken(token);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("unexpected algorithm");
  });

  it("rejects a non-EdDSA algorithm", async () => {
    const token = handcraftedToken({ alg: "HS256", kid: KID }, adminPayload());
    const result = await verifyEduAdminToken(token);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("unexpected algorithm");
  });

  it("rejects a missing kid", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ kid: null }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("missing key id");
  });

  it("rejects an unknown kid", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ kid: "no-such-key" }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("unknown signing key");
  });

  it("accepts a kid that appears on JWKS refresh (rotation)", async () => {
    const rotatedJwk = { ...jwk, kid: "rotated-key-2" };
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        calls++;
        const keys = calls === 1 ? [jwk] : [jwk, rotatedJwk];
        return new Response(JSON.stringify({ keys }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }),
    );
    const result = await verifyEduAdminToken(
      await makeAdminToken({ kid: "rotated-key-2" }),
    );
    expect(result.ok).toBe(true);
    expect(calls).toBe(2);
  });

  it("rejects a bad signature", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ key: otherPrivateKey }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a wrong issuer", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ iss: "https://evil.example" }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects the gameplay audience", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ aud: GAMEPLAY_AUDIENCE }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.reason).toBe("not an admin capability token (audience)");
  });

  it("rejects a multi-element audience array even if it contains the admin audience", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ aud: [ADMIN_AUDIENCE, "something-else"] }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.reason).toBe("not an admin capability token (audience)");
  });

  it("rejects an audience array without the admin audience", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ aud: ["something-else"] }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a missing scope", async () => {
    // JSON drops undefined, so scope is absent from the payload.
    const noScope = await new SignJWT({ ...adminPayload(), scope: undefined })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(privateKey);
    const result = await verifyEduAdminToken(noScope);
    expect(result.ok).toBe(false);
  });

  it("rejects a wrong scope", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ scope: "openfront:read" }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.reason).toBe("not an admin capability token (scope)");
  });

  it("rejects a scope that merely contains the admin scope as a substring", async () => {
    // Discrete space-separated matching: "openfront:adminx" must not grant.
    const result = await verifyEduAdminToken(
      await makeAdminToken({ scope: "openfront:adminx" }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a missing sub", async () => {
    // JSON drops undefined, so sub is absent from the payload.
    const noSub = await new SignJWT({ ...adminPayload(), sub: undefined })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(privateKey);
    const result = await verifyEduAdminToken(noSub);
    expect(result.ok).toBe(false);
  });

  it("rejects a non-UUID-shaped sub", async () => {
    const badSub = await makeAdminToken({ sub: "not-a-uuid" });
    expect((await verifyEduAdminToken(badSub)).ok).toBe(false);
    const shortSub = await makeAdminToken({
      sub: Buffer.from([1, 2, 3]).toString("base64url"),
    });
    expect((await verifyEduAdminToken(shortSub)).ok).toBe(false);
  });

  it("rejects a missing iat", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ omitIat: true }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a missing exp", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ omitExp: true }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a 61s lifetime", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyEduAdminToken(
      await makeAdminToken({ iat: now, exp: now + 61 }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.reason).toBe("token lifetime exceeds maximum");
  });

  it("rejects a zero lifetime", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyEduAdminToken(
      await makeAdminToken({ iat: now + 30, exp: now + 30 }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a negative lifetime", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyEduAdminToken(
      await makeAdminToken({ iat: now + 3, exp: now + 2 }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyEduAdminToken(
      await makeAdminToken({ iat: now - 60, exp: now - 10 }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a token issued in the future", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyEduAdminToken(
      await makeAdminToken({ iat: now + 30, exp: now + 60 }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("token issued in the future");
  });

  it("rejects a provider mismatch", async () => {
    const result = await verifyEduAdminToken(
      await makeAdminToken({ provider: "google" }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects when the JWKS is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    const result = await verifyEduAdminToken(await makeAdminToken());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("unknown signing key");
  });
});

describe("isAdminCapabilityToken (routing check)", () => {
  it("is true for an admin-shaped token", async () => {
    expect(isAdminCapabilityToken(await makeAdminToken())).toBe(true);
  });

  it("is false for a gameplay-shaped token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      iss: ISSUER,
      aud: GAMEPLAY_AUDIENCE,
      sub: uuidToBase64url(ACCOUNT_UUID),
      provider: "pocketedu",
      name: "Test Player",
      jti: randomUUID(),
      iat: now,
      exp: now + 120,
    })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(privateKey);
    expect(isAdminCapabilityToken(token)).toBe(false);
  });

  it("is false for garbage", () => {
    expect(isAdminCapabilityToken("garbage")).toBe(false);
    expect(isAdminCapabilityToken("a.b.c")).toBe(false);
  });

  it("reads the configured issuer/audience from env", () => {
    expect(eduAdminIssuer()).toBe(ISSUER);
    expect(eduAdminAudience()).toBe(ADMIN_AUDIENCE);
  });
});

describe("hasAdminCapabilityMarker (gameplay-side confusion check)", () => {
  it("is true for a full admin capability", async () => {
    expect(hasAdminCapabilityMarker(await makeAdminToken())).toBe(true);
  });

  it("is true for the admin audience alone", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      iss: ISSUER,
      aud: ADMIN_AUDIENCE,
      sub: uuidToBase64url(ACCOUNT_UUID),
      provider: "pocketedu",
      iat: now,
      exp: now + 120,
    })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(privateKey);
    expect(hasAdminCapabilityMarker(token)).toBe(true);
    // ...but it is not a complete admin capability (no scope).
    expect(isAdminCapabilityToken(token)).toBe(false);
  });

  it("is true for the admin scope alone", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      iss: ISSUER,
      aud: GAMEPLAY_AUDIENCE,
      sub: uuidToBase64url(ACCOUNT_UUID),
      provider: "pocketedu",
      scope: "openfront:admin",
      iat: now,
      exp: now + 120,
    })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(privateKey);
    expect(hasAdminCapabilityMarker(token)).toBe(true);
    expect(isAdminCapabilityToken(token)).toBe(false);
  });

  it("is false for a clean gameplay token or garbage", async () => {
    const now = Math.floor(Date.now() / 1000);
    const gameplay = await new SignJWT({
      iss: ISSUER,
      aud: GAMEPLAY_AUDIENCE,
      sub: uuidToBase64url(ACCOUNT_UUID),
      provider: "pocketedu",
      iat: now,
      exp: now + 120,
    })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(privateKey);
    expect(hasAdminCapabilityMarker(gameplay)).toBe(false);
    expect(hasAdminCapabilityMarker("garbage")).toBe(false);
  });
});

describe("bidirectional token separation", () => {
  async function makeGameplayToken(
    extra: Record<string, unknown> = {},
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      iss: ISSUER,
      aud: GAMEPLAY_AUDIENCE,
      sub: uuidToBase64url(ACCOUNT_UUID),
      provider: "pocketedu",
      name: "Test Player",
      jti: randomUUID(),
      iat: now,
      exp: now + 120,
      ...extra,
    })
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(privateKey);
  }

  it("rejects an admin token presented as a gameplay credential", async () => {
    const adminToken = await makeAdminToken();
    const result = await verifyPocketEduToken(adminToken);
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.reason).toBe(
        "admin capability presented as gameplay credential",
      );
  });

  it("rejects a gameplay token carrying the admin scope as a gameplay credential", async () => {
    const sneaky = await makeGameplayToken({ scope: "openfront:admin" });
    const result = await verifyPocketEduToken(sneaky);
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.reason).toBe(
        "admin capability presented as gameplay credential",
      );
  });

  it("rejects a gameplay token presented as an admin capability", async () => {
    const gameplayToken = await makeGameplayToken();
    const result = await verifyEduAdminToken(gameplayToken);
    expect(result.ok).toBe(false);
  });

  it("still accepts a valid gameplay token (no false positive)", async () => {
    const gameplayToken = await makeGameplayToken();
    const result = await verifyPocketEduToken(gameplayToken);
    expect(result.ok).toBe(true);
  });
});
