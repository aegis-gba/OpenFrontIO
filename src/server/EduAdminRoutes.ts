import type { Express, Request, Response } from "express";
import type { Logger } from "winston";
import { z } from "zod";
import { ID, type Intent } from "../core/Schemas";
import { verifyEduAdminToken } from "./eduAdminAuth";
import type { GameManager } from "./GameManager";
import type { IntentActor } from "./IntentAuthorization";
import { ServerEnv } from "./ServerEnv";

// ---------------------------------------------------------------------------
// Pocket Edu admin command API.
//
// A SEPARATE credential from gameplay auth: callers present a short-lived
// Pocket Edu admin capability JWT (./eduAdminAuth, `scope` includes
// `openfront:admin`, audience `pocketedu-openfront-admin`). A gameplay JWT is
// never accepted here, and an admin JWT is never accepted as a gameplay
// credential.
//
// The actor is built solely from the verified token's `sub` claim, mapped
// through the same ACCOUNT identity namespace the gameplay path uses. Admin
// status is never inferred from `role`, display names, public profile ids,
// lobby-creator status, or any client-claimed field.
//
// Every action is logged server-side with the actor's persistentId, the game
// id, and the action. No token material is ever logged.
//
// Routing: these mount on the worker app at /api/admin/..., so they are
// reached externally as /w0/api/admin/... (the adapter strips /w0 and
// proxies to the worker; /w0/api/create_game already proves the path).
// CORS comes from gameApiCors (Worker mounts it on /api and /^\/w\d+\/api/)
// and the worker-wide HTTP rate limit applies.
// ---------------------------------------------------------------------------

// The edu-admin actor: an admin with no lobby seat. clientID is namespaced so
// it can never collide with a real player id (and therefore can never
// self-kick); the "no connected client" telemetry lookup in handleIntent
// simply skips it, like the admin bot's intents.
function eduAdminActor(persistentId: string): IntentActor {
  return {
    clientID: `edu-admin:${persistentId}`,
    isLobbyCreator: false,
    isAdmin: true,
    isAdminBot: false,
    isEduAdmin: true,
  };
}

const KickBodySchema = z
  .object({
    // Live clientID (lobby / in-game kick) OR the account publicId shown in
    // the roster, for callers that identify a player by account. Exactly one.
    clientID: z.string().min(1).max(100).optional(),
    publicID: z.string().min(1).max(100).optional(),
    // Free-form note recorded in the server log. The kick delivered to the
    // client uses the server's standard admin kick reason.
    reason: z.string().max(200).optional(),
  })
  .refine(
    (d) =>
      (d.clientID !== undefined ? 1 : 0) +
        (d.publicID !== undefined ? 1 : 0) ===
      1,
    { message: "exactly one of clientID, publicID is required" },
  );

export function registerEduAdminRoutes(opts: {
  app: Express;
  gm: GameManager;
  workerId: number;
  log: Logger;
}) {
  const { app, gm, workerId, log } = opts;

  // Verify the admin capability JWT. Returns the actor's persistentId, or
  // null after sending the 401 (generic message; the verifier logs the
  // specific reason server-side).
  const authenticate = async (
    req: Request,
    res: Response,
  ): Promise<string | null> => {
    const authHeader = req.headers.authorization;
    if (typeof authHeader !== "string" || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({ error: "Unauthorized" });
      return null;
    }
    const result = await verifyEduAdminToken(
      authHeader.substring("Bearer ".length),
    );
    if (!result.ok) {
      res.status(401).json({ error: "Unauthorized" });
      return null;
    }
    return result.identity.persistentId;
  };

  // Validate game id format and that this worker owns it. 404 on every miss
  // (bad id, misrouted, unknown game) so the routes don't leak sharding.
  const ownsGame = (id: string, res: Response): boolean => {
    if (!ID.safeParse(id).success) {
      res.status(404).json({ error: "Game not found" });
      return false;
    }
    if (ServerEnv.workerIndex(id) !== workerId) {
      res.status(404).json({ error: "Game not found" });
      return false;
    }
    return true;
  };

  // Read game info + live stats. liveStats is null until clients reach their
  // first consensus (same semantics as the admin-bot stats route).
  app.get("/api/admin/game/:id", async (req, res) => {
    try {
      const persistentId = await authenticate(req, res);
      if (persistentId === null) return;
      const id = req.params.id as string;
      if (!ownsGame(id, res)) return;
      const game = gm.game(id);
      if (game === null) {
        return res.status(404).json({ error: "Game not found" });
      }
      log.info("edu admin read game", { gameID: id, actor: persistentId });
      res.json({ game: game.gameInfo(), stats: game.liveStats() });
    } catch (e) {
      log.warn("edu admin game read failed", {
        error: e instanceof Error ? e.message : String(e),
      });
      res.status(500).json({ error: "Internal error" });
    }
  });

  // Who is in this game. Same roster the lobby sees.
  app.get("/api/admin/game/:id/roster", async (req, res) => {
    try {
      const persistentId = await authenticate(req, res);
      if (persistentId === null) return;
      const id = req.params.id as string;
      if (!ownsGame(id, res)) return;
      const game = gm.game(id);
      if (game === null) {
        return res.status(404).json({ error: "Game not found" });
      }
      log.info("edu admin read roster", { gameID: id, actor: persistentId });
      res.json({ roster: game.roster() });
    } catch (e) {
      log.warn("edu admin roster read failed", {
        error: e instanceof Error ? e.message : String(e),
      });
      res.status(500).json({ error: "Internal error" });
    }
  });

  // Kick a player. Goes through the universal handleIntent path with the
  // edu-admin actor, so all the kick guards (incl. the listed-lobby admin
  // carve-out) apply exactly as for other admins. Kicking bans the player's
  // persistentID: there is deliberately no unban API.
  app.post("/api/admin/game/:id/kick", async (req, res) => {
    try {
      const persistentId = await authenticate(req, res);
      if (persistentId === null) return;
      const id = req.params.id as string;
      if (!ownsGame(id, res)) return;
      const parsed = KickBodySchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        return res.status(400).json({ error: z.prettifyError(parsed.error) });
      }
      const game = gm.game(id);
      if (game === null) {
        return res.status(404).json({ error: "Game not found" });
      }
      // Built directly (not re-parsed through IntentSchema): the MappedID
      // regex would wrongly reject real dashed-UUID publicIds, while
      // handleIntent resolves either form by plain string comparison.
      const intent: Intent = {
        type: "kick_player",
        targetClientID: parsed.data.clientID,
        targetPublicID: parsed.data.publicID,
      };
      const result = game.handleIntent(intent, eduAdminActor(persistentId));
      if (result.status !== 200) {
        return res
          .status(result.status)
          .json({ error: result.error ?? "error" });
      }
      log.info("edu admin kicked player", {
        gameID: id,
        actor: persistentId,
        targetClientID: parsed.data.clientID,
        targetPublicID: parsed.data.publicID,
        reason: parsed.data.reason,
      });
      res.json({ kicked: true });
    } catch (e) {
      log.warn("edu admin kick failed", {
        error: e instanceof Error ? e.message : String(e),
      });
      res.status(500).json({ error: "Internal error" });
    }
  });

  // Force-start: ensure the game starts. Mirrors the lobby creator's start
  // (the toggle_game_start_timer intent path, including its countdown). A
  // no-op when the game already started or a start countdown is running —
  // toggling in that state would cancel the countdown, the opposite of
  // starting.
  app.post("/api/admin/game/:id/start", async (req, res) => {
    try {
      const persistentId = await authenticate(req, res);
      if (persistentId === null) return;
      const id = req.params.id as string;
      if (!ownsGame(id, res)) return;
      const game = gm.game(id);
      if (game === null) {
        return res.status(404).json({ error: "Game not found" });
      }
      if (game.hasStarted() || game.gameInfo().startsAt !== undefined) {
        log.info("edu admin force-start no-op (already started/starting)", {
          gameID: id,
          actor: persistentId,
        });
        return res.json({ started: true, alreadyStarted: true });
      }
      const intent: Intent = { type: "toggle_game_start_timer" };
      const result = game.handleIntent(intent, eduAdminActor(persistentId));
      if (result.status !== 200) {
        return res
          .status(result.status)
          .json({ error: result.error ?? "error" });
      }
      log.info("edu admin force-started game", {
        gameID: id,
        actor: persistentId,
      });
      res.json({ started: true, alreadyStarted: false });
    } catch (e) {
      log.warn("edu admin force-start failed", {
        error: e instanceof Error ? e.message : String(e),
      });
      res.status(500).json({ error: "Internal error" });
    }
  });

  // End the game: closes every client connection. Ended lobbies are pruned
  // by the game manager as usual.
  app.post("/api/admin/game/:id/end", async (req, res) => {
    try {
      const persistentId = await authenticate(req, res);
      if (persistentId === null) return;
      const id = req.params.id as string;
      if (!ownsGame(id, res)) return;
      const game = gm.game(id);
      if (game === null) {
        return res.status(404).json({ error: "Game not found" });
      }
      await game.end();
      log.info("edu admin ended game", { gameID: id, actor: persistentId });
      res.json({ ended: true });
    } catch (e) {
      log.warn("edu admin end failed", {
        error: e instanceof Error ? e.message : String(e),
      });
      res.status(500).json({ error: "Internal error" });
    }
  });
}
