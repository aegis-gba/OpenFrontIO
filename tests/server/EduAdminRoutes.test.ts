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

function routes(game: unknown, gmOver: Record<string, unknown> = {}) {
  const table: Record<string, (req: any, res: any) => Promise<void>> = {};
  const app: any = {
    get(path: string, ...h: ((req: any, res: any) => Promise<void>)[]) {
      table[path] = h[h.length - 1];
    },
    post(path: string, ...h: ((req: any, res: any) => Promise<void>)[]) {
      table[path] = h[h.length - 1];
    },
  };
  const gm: any = { game: () => game, createGame: vi.fn(() => null), ...gmOver };
  const log: any = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
  registerEduAdminRoutes({ app, gm, workerId: 0, log });
  return { table, log, gm };
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
    isPaused: () => false,
    admitAsPlayer: vi.fn(() => true),
    hasPlayerSeat: vi.fn(() => false),
    gameConfig: { gameMap: "World" },
    setSuccessorLobby: vi.fn(),
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

describe("POST /api/admin/game/:id/unkick", () => {
  const path = "/api/admin/game/:id/unkick";

  it("unkicks by clientID through the edu-admin actor", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken(), { clientID: "c1" }), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ unkicked: true });
    expect(game.handleIntent).toHaveBeenCalledWith(
      { type: "unkick_player", targetClientID: "c1", targetPublicID: undefined },
      EXPECTED_ACTOR,
    );
  });

  it("unkicks by publicID", async () => {
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
        type: "unkick_player",
        targetClientID: undefined,
        targetPublicID: "pub-1",
      },
      EXPECTED_ACTOR,
    );
  });

  it("400s when both or neither target is given", async () => {
    const { table } = routes(mockGame());
    const token = await makeAdminToken();
    for (const body of [{ clientID: "c1", publicID: "pub-1" }, {}]) {
      const res = mockRes();
      await table[path](authReq(token, body), res);
      expect(res.statusCode).toBe(400);
    }
  });

  it("maps a not-banned target through as 404", async () => {
    const game = mockGame({
      handleIntent: vi.fn(() => ({ status: 404, error: "player is not banned" })),
    });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { clientID: "c1" }),
      res,
    );
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({ error: "player is not banned" });
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

describe("POST /api/admin/game/:id/pause and /resume", () => {
  const pausePath = "/api/admin/game/:id/pause";
  const resumePath = "/api/admin/game/:id/resume";

  it("pauses a running game", async () => {
    const game = mockGame({ hasStarted: () => true });
    const { table } = routes(game);
    const res = mockRes();
    await table[pausePath](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ paused: true, alreadyPaused: false });
    expect(game.handleIntent).toHaveBeenCalledWith(
      { type: "toggle_pause", paused: true },
      EXPECTED_ACTOR,
    );
  });

  it("pause is a no-op when already paused", async () => {
    const game = mockGame({ hasStarted: () => true, isPaused: () => true });
    const { table } = routes(game);
    const res = mockRes();
    await table[pausePath](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ paused: true, alreadyPaused: true });
    expect(game.handleIntent).not.toHaveBeenCalled();
  });

  it("pause 409s when the game has not started", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[pausePath](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(409);
    expect(game.handleIntent).not.toHaveBeenCalled();
  });

  it("resumes a paused game", async () => {
    const game = mockGame({ hasStarted: () => true, isPaused: () => true });
    const { table } = routes(game);
    const res = mockRes();
    await table[resumePath](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ paused: false, alreadyResumed: false });
    expect(game.handleIntent).toHaveBeenCalledWith(
      { type: "toggle_pause", paused: false },
      EXPECTED_ACTOR,
    );
  });

  it("resume is a no-op when not paused", async () => {
    const game = mockGame({ hasStarted: () => true });
    const { table } = routes(game);
    const res = mockRes();
    await table[resumePath](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ paused: false, alreadyResumed: true });
    expect(game.handleIntent).not.toHaveBeenCalled();
  });

  it("401s without a token", async () => {
    const { table } = routes(mockGame({ hasStarted: () => true }));
    const res = mockRes();
    await table[pausePath](noAuthReq(), res);
    expect(res.statusCode).toBe(401);
  });
});

describe("POST /api/admin/game/:id/config", () => {
  const path = "/api/admin/game/:id/config";

  it("updates the game config via the edu-admin actor", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { maxPlayers: 10 }),
      res,
    );
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ updated: true });
    expect(game.handleIntent).toHaveBeenCalledWith(
      { type: "update_game_config", config: { maxPlayers: 10 } },
      EXPECTED_ACTOR,
    );
  });

  it("400s on an invalid config value", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { maxPlayers: "ten" }),
      res,
    );
    expect(res.statusCode).toBe(400);
    expect(game.handleIntent).not.toHaveBeenCalled();
  });

  it("maps the intent's 409 when the game already started", async () => {
    const game = mockGame({
      handleIntent: vi.fn(() => ({
        status: 409,
        error: "game already started",
      })),
    });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { maxPlayers: 10 }),
      res,
    );
    expect(res.statusCode).toBe(409);
    expect(res.body).toEqual({ error: "game already started" });
  });
});

describe("POST /api/admin/game/:id/cheats", () => {
  const path = "/api/admin/game/:id/cheats";

  it("enables host cheats", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), {
        infiniteGold: true,
        infiniteTroops: true,
      }),
      res,
    );
    expect(res.statusCode).toBe(200);
    expect(game.handleIntent).toHaveBeenCalledWith(
      {
        type: "update_game_config",
        config: {
          hostCheats: {
            infiniteGold: true,
            infiniteTroops: true,
            goldMultiplier: undefined,
            startingGold: undefined,
          },
        },
      },
      EXPECTED_ACTOR,
    );
    expect(res.body.cheats).toMatchObject({
      infiniteGold: true,
      infiniteTroops: true,
    });
  });

  it("disables cheats with enabled:false", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken(), { enabled: false }), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ cheats: null });
    expect(game.handleIntent).toHaveBeenCalledWith(
      { type: "update_game_config", config: { hostCheats: undefined } },
      EXPECTED_ACTOR,
    );
  });

  it("accepts cheat tuning values", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { goldMultiplier: 10, startingGold: 5000 }),
      res,
    );
    expect(res.statusCode).toBe(200);
    expect(game.handleIntent).toHaveBeenCalledWith(
      {
        type: "update_game_config",
        config: {
          hostCheats: {
            infiniteGold: undefined,
            infiniteTroops: undefined,
            goldMultiplier: 10,
            startingGold: 5000,
          },
        },
      },
      EXPECTED_ACTOR,
    );
  });
});

describe("POST /api/admin/game/:id/late_join", () => {
  const path = "/api/admin/game/:id/late_join";

  it("seats a spectator as a player before the game starts", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken(), { clientID: "c1" }), res);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ admitted: true, as: "player" });
    expect(game.admitAsPlayer).toHaveBeenCalledWith("c1");
  });

  it("resolves the target by publicID from the roster", async () => {
    const game = mockGame({
      roster: () => [
        { clientID: "c9", username: "late", publicId: "pub-9" },
      ],
    });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { publicID: "pub-9" }),
      res,
    );
    expect(res.statusCode).toBe(200);
    expect(game.admitAsPlayer).toHaveBeenCalledWith("c9");
  });

  it("404s an unknown target", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](
      authReq(await makeAdminToken(), { publicID: "nobody" }),
      res,
    );
    expect(res.statusCode).toBe(404);
  });

  it("lets a seated player rejoin a started game", async () => {
    const game = mockGame({
      hasStarted: () => true,
      hasPlayerSeat: vi.fn(() => true),
    });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken(), { clientID: "c1" }), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.admitted).toBe(true);
    expect(res.body.as).toBe("rejoin");
    expect(game.admitAsPlayer).not.toHaveBeenCalled();
  });

  it("409s a brand-new arrival to a started game with a remake hint", async () => {
    const game = mockGame({ hasStarted: () => true });
    const { table } = routes(game);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken(), { clientID: "c1" }), res);
    expect(res.statusCode).toBe(409);
    expect(res.body.error).toBe("game already started");
    expect(res.body.suggestion).toContain("remake");
  });
});

describe("POST /api/admin/game/:id/remake", () => {
  const path = "/api/admin/game/:id/remake";

  it("creates a successor lobby, broadcasts it, then ends the old game", async () => {
    const game = mockGame();
    const newGame = mockGame();
    const { table, gm } = routes(game, {
      createGame: vi.fn(() => newGame),
      game: (id: string) => (id === "aaaaaaaa" ? game : null),
    });
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.remade).toBe(true);
    const newId = res.body.newGameID as string;
    expect(newId).toMatch(/^\d{4}$/);
    expect(gm.createGame).toHaveBeenCalledWith(
      newId,
      expect.objectContaining({ gameMap: "World" }),
    );
    // Successor broadcast happens before the old game ends.
    expect(game.setSuccessorLobby).toHaveBeenCalledWith(newId);
    expect(game.end).toHaveBeenCalled();
    const setOrder = (game.setSuccessorLobby as any).mock.invocationCallOrder[0];
    const endOrder = (game.end as any).mock.invocationCallOrder[0];
    expect(setOrder).toBeLessThan(endOrder);
  });

  it("404s an unknown game", async () => {
    const { table } = routes(null);
    const res = mockRes();
    await table[path](authReq(await makeAdminToken()), res);
    expect(res.statusCode).toBe(404);
  });

  it("401s without a token", async () => {
    const game = mockGame();
    const { table } = routes(game);
    const res = mockRes();
    await table[path](noAuthReq(), res);
    expect(res.statusCode).toBe(401);
    expect(game.end).not.toHaveBeenCalled();
  });
});
