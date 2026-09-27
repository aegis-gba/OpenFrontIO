/**
 * @vitest-environment node
 */
import { randomUUID } from "crypto";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { uuidToBase64url } from "../../src/core/Base64";
import { registerEduAdminRoutes } from "../../src/server/EduAdminRoutes";
import { deriveAccountPersistentId } from "../../src/server/identityNamespaces";
import { _resetPocketEduJwksCacheForTests } from "../../src/server/pocketEduAuth";
import { ServerEnv } from "../../src/server/ServerEnv";

// Route-level tests for the Pocket Edu admin command API, using the same
// mock-app-table pattern as the admin-bot route tests: no HTTP server, no
// real GameManager. The auth path is real — a fresh Ed25519 keypair stands
// in for Pocket Edu's issuer and the JWKS endpoint is stubbed — so these
// tests prove the routes accept exactly the admin capability JWT and
// nothing else.

const ISSUER = "https://pocketedu.test";
const GAMEPLAY_AUDIENCE = "pocketedu-openfront-test";
const ADMIN_AUDIENCE = "pocketedu-openfront-admin-test";
const JWKS_URL = "https://pocketedu.test/.well-known/openfront-jwks.json";
const KID = "test-admin-key-1";
const ACCOUNT_UUID = "123e4567-e89b-12d3-a456-426614174000";
const PERSISTENT_ID = deriveAccountPersistentId(ACCOUNT_UUID);
const GAME_ID = "aaaaaaaa";

let privateKey: CryptoKey;
let jwk: JWK;

function stubJwks() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url === JWKS_URL) {
        return new Response(JSON.stringify({ keys: [jwk] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch of ${url}`);
    }),
  );
}

async function makeAdminToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: ISSUER,
    aud: ADMIN_AUDIENCE,
    sub: uuidToBase64url(ACCOUNT_UUID),
    provider: "pocketedu",
    scope: "openfront:admin",
    iat: now,
    exp: now + 30,
  })
    .setProtectedHeader({ alg: "EdDSA", kid: KID })
    .sign(privateKey);
}

async function makeGameplayToken(): Promise<string> {
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
  })
    .setProtectedHeader({ alg: "EdDSA", kid: KID })
    .sign(privateKey);
}

function routes(game: unknown) {
  const table: Record<string, (req: any, res: any) => Promise<void>> = {};
  const app: any = {
    get(path: string, ...h: ((req: any, res: any) => Promise<void>)[]) {
      table[path] = h[h.length - 1];
    },
    post(path: string, ...h: ((req: any, res: any) => Promise<void>)[]) {
      table[path] = h[h.length - 1];
    },
  };
  const gm: any = { game: () => game };
  const log: any = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
  registerEduAdminRoutes({ app, gm, workerId: 0, log });
  return { table, log };
}

function mockRes() {
  const res: any = {
    statusCode: 200,
    body: undefined,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

function mockGame(over: Record<string, unknown> = {}) {
  return {
    gameInfo: () => ({ startsAt: undefined }),
    liveStats: () => null,
    roster: () => [{ clientID: "c1", username: "ana" }],
    hasStarted: () => false,
    handleIntent: vi.fn(() => ({ status: 200 })),
    end: vi.fn(async () => {}),
    ...over,
  };
}

const authReq = (token: string, body?: unknown) => ({
  params: { id: GAME_ID },
  headers: { authorization: `Bearer ${token}` },
  body,
});
const noAuthReq = (body?: unknown) => ({
  params: { id: GAME_ID },
  headers: {},
  body,
});

const EXPECTED_ACTOR = {
  clientID: `edu-admin:${PERSISTENT_ID}`,
  isLobbyCreator: false,
  isAdmin: true,
  isAdminBot: false,
  isEduAdmin: true,
};

beforeEach(async () => {
  vi.stubEnv("POCKET_EDU_AUTH_ISSUER", ISSUER);
  vi.stubEnv("POCKET_EDU_ADMIN_AUDIENCE", ADMIN_AUDIENCE);
  vi.stubEnv("POCKET_EDU_ADMIN_JWKS_URL", JWKS_URL);
  _resetPocketEduJwksCacheForTests();
  if (!privateKey) {
    const pair = await generateKeyPair("EdDSA");
    privateKey = pair.privateKey;
    jwk = await exportJWK(pair.publicKey);
    jwk.kid = KID;
    jwk.alg = "EdDSA";
  }
  stubJwks();
  vi.spyOn(ServerEnv, "workerIndex").mockReturnValue(0);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("GET /api/admin/game/:id", () => {
  const path = "/api/admin/game/:id";

  it("401s without a token", async () => {
    const { table } = routes(mockGame());
    const res = mockRes();
    await table[path](noAuthReq(), res);
    expect(res.statusCode).toBe(401);
  });

  it("401s on a bad token", async () => {
    const { table } = routes(mockGame());
    const res = mockRes();
    await table[path](authReq("bogus"), res);
    expect(res.statusCode).toBe(401);
  });

  it("401s on a valid gameplay token (not an admin capability)", async () => {
    const { table } = routes(mockGame());
    const res = mockRes();
    await table[path](authReq(await makeGameplayToken()), res);
    expect(res.statusCode).toBe(401);
  });

  it("returns game info + stats for a valid admin token", async () => {
    const game = mockGame({
      gameInfo: () => ({ gameID: GAME_ID, startsAt: undefined }),
      liveStats: () => ({ tick: 42 }),
    });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.game.gameID).toBe(GAME_ID);
    expect(res.body.stats).toEqual({ tick: 42 });
  });

  it("404s a misrouted game", async () => {
    vi.spyOn(ServerEnv, "workerIndex").mockReturnValue(1);
    const { table } = routes(mockGame());
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(404);
  });

  it("404s an unknown game", async () => {
    const { table } = routes(null);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(404);
  });

  it("404s a malformed game id", async () => {
    const { table } = routes(mockGame());
    const res = mockRes();
    await table[path](
      { ...authReq(await makeAdminToken()), params: { id: "nope!" } },
      res,
    );
    expect(res.statusCode).toBe(404);
  });

  it("logs the actor's persistentId, never token material", async () => {
    const game = mockGame();
    const { table, log } = routes(game);
    const res = mockRes();
    const token = await makeAdminToken();
    await table[path](authReq(token), res);
    expect(res.statusCode).toBe(200);
    expect(log.info).toHaveBeenCalledWith(
      "edu admin read game",
      expect.objectContaining({ gameID: GAME_ID, actor: PERSISTENT_ID }),
    );
    const logged = JSON.stringify(log.info.mock.calls);
    expect(logged).not.toContain(token);
  });
});

describe("GET /api/admin/game/:id/roster", () => {
  const path = "/api/admin/game/:id/roster";

  it("401s without a token", async () => {
    const { table } = routes(mockGame());
    const res = mockRes();
    await table[path](noAuthReq(), res);
    expect(res.statusCode).toBe(401);
  });

  it("returns the roster for a valid admin token", async () => {
    const { table } = routes(mockGame());
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.roster).toEqual([{ clientID: "c1", username: "ana" }]);
  });
});

describe("POST /api/admin/game/:id/kick", () => {
  const path = "/api/admin/game/:id/kick";

  it("kicks by clientID through the edu-admin actor", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken(), { clientID: "c1" }), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ kicked: true });
    expect(game.handleIntent).toHaveBeenCalledWith(
      { type: "kick_player", targetClientID: "c1", targetPublicID: undefined },
      EXPECTED_ACTOR,
    );
  });

  it("kicks by publicID", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { publicID: "pub-1" }),
      res,
    );
    expect(res.statusCode).toBe(200);
    expect(game.handleIntent).toHaveBeenCalledWith(
      {
        type: "kick_player",
        targetClientID: undefined,
        targetPublicID: "pub-1",
      },
      EXPECTED_ACTOR,
    );
  });

  it("400s when both or neither target is given", async () => {
    const { table } = routes(mockGame());
    const token = await makeAdminToken();
    for (const body of [
      { clientID: "c1", publicID: "pub-1" },
      {},
      { reason: "no target" },
    ]) {
      const res = mockRes();
      await table[path](authReq(token, body), res);
      expect(res.statusCode).toBe(400);
    }
  });

  it("maps the intent's failure status through", async () => {
    const game = mockGame({
      handleIntent: vi.fn(() => ({ status: 404, error: "no such player" })),
    });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { clientID: "ghost" }),
      res,
    );
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({ error: "no such player" });
  });

  it("401s on a gameplay token", async () => {
    const { table } = routes(mockGame());
    const res = mockRes();
    await table[path](
      authReq(await makeGameplayToken(), { clientID: "c1" }),
      res,
    );
    expect(res.statusCode).toBe(401);
  });
});

describe("POST /api/admin/game/:id/start", () => {
  const path = "/api/admin/game/:id/start";

  it("starts an unstarted game via the start-timer intent", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ started: true, alreadyStarted: false });
    expect(game.handleIntent).toHaveBeenCalledWith(
      { type: "toggle_game_start_timer" },
      EXPECTED_ACTOR,
    );
  });

  it("is a no-op when the game already started", async () => {
    const game = mockGame({ hasStarted: () => true });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ started: true, alreadyStarted: true });
    expect(game.handleIntent).not.toHaveBeenCalled();
  });

  it("is a no-op when a start countdown is already running", async () => {
    const game = mockGame({ gameInfo: () => ({ startsAt: 1234567890 }) });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ started: true, alreadyStarted: true });
    // Must not toggle: that would CANCEL the running countdown.
    expect(game.handleIntent).not.toHaveBeenCalled();
  });
});

describe("POST /api/admin/game/:id/end", () => {
  const path = "/api/admin/game/:id/end";

  it("ends the game", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ ended: true });
    expect(game.end).toHaveBeenCalled();
  });

  it("401s without a token", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](noAuthReq(), res);
    expect(res.statusCode).toBe(401);
    expect(game.end).not.toHaveBeenCalled();
  });

  it("404s an unknown game", async () => {
    const { table } = routes(null);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(404);
  });
});
