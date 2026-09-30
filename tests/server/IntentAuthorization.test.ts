import { describe, expect, it } from "vitest";
import { GameType } from "../../src/core/game/Game";
import { GameConfig, Intent } from "../../src/core/Schemas";
import {
  authorizeIntent,
  IntentActor,
  IntentGameState,
} from "../../src/server/IntentAuthorization";
import { cid } from "../util/GameServerHarness";

// The guards on their own, as a table. What an authorized intent then does —
// kicking, config patching, the start timer, pausing, queueing — is covered
// through GameServer in AdminBotIntent, HostedLobbyListing and the golden
// transcript.

const actor = (over: Partial<IntentActor> = {}): IntentActor => ({
  clientID: cid("p1"),
  isLobbyCreator: false,
  isAdmin: false,
  isAdminBot: false,
  ...over,
});
const player = actor();
const host = actor({ isLobbyCreator: true });
const admin = actor({ isAdmin: true });
const bot = actor({ isAdmin: true, isAdminBot: true });
// Pocket Edu admin capability (./eduAdminAuth): an admin with no lobby seat,
// authorized wherever the admin bot is, but without its public-game refusal.
const eduAdmin = actor({ isAdmin: true, isEduAdmin: true });

const lobby = (over: Partial<IntentGameState> = {}): IntentGameState => ({
  isPublic: false,
  isListed: false,
  hasStarted: false,
  ...over,
});

const kick: Intent = { type: "kick_player", targetClientID: cid("p2") };
const unkick: Intent = { type: "unkick_player", targetClientID: cid("p2") };
const config = (c: Partial<GameConfig>): Intent => ({
  type: "update_game_config",
  config: c,
});
const timer: Intent = { type: "toggle_game_start_timer" };
const pause: Intent = { type: "toggle_pause", paused: true };
const spawn: Intent = { type: "spawn", tile: 1 };
const grant: Intent = {
  type: "admin_grant",
  target: cid("p2"),
  gold: 1000,
  troops: null,
};
const revive: Intent = { type: "admin_revive", target: cid("p2") };
const bibisWrath: Intent = {
  type: "admin_bibis_wrath",
  target: cid("p2"),
  adminName: "Boss",
  targetName: "PlayerTwo",
  isNPC: false,
};

describe("authorizeIntent", () => {
  it.each<[string, Intent, IntentActor, IntentGameState, number | null]>([
    // The admin bot is refused any intent on a public game, before anything
    // else is considered.
    ["bot on a public game", spawn, bot, lobby({ isPublic: true }), 403],
    ["bot kick on a public game", kick, bot, lobby({ isPublic: true }), 403],
    // Unlike the bot, the edu admin has no blanket public-game refusal: it
    // moderates public games too, so kick goes through.
    [
      "edu admin kick on a public game",
      kick,
      eduAdmin,
      lobby({ isPublic: true }),
      null,
    ],

    [
      "mark_disconnected from anyone",
      { type: "mark_disconnected", isDisconnected: true },
      host,
      lobby(),
      400,
    ],

    ["kick by a player", kick, player, lobby(), 403],
    ["kick by the host", kick, host, lobby(), null],
    [
      "kick by the host of a listed lobby",
      kick,
      host,
      lobby({ isListed: true }),
      403,
    ],
    [
      "kick by an admin in a listed lobby",
      kick,
      admin,
      lobby({ isListed: true }),
      null,
    ],
    [
      "kick by the bot in a listed lobby",
      kick,
      bot,
      lobby({ isListed: true }),
      null,
    ],
    ["kick by edu admin", kick, eduAdmin, lobby(), null],
    [
      "kick by edu admin in a listed lobby",
      kick,
      eduAdmin,
      lobby({ isListed: true }),
      null,
    ],
    [
      "kick by the host of a listed game that started",
      kick,
      host,
      lobby({ isListed: true, hasStarted: true }),
      403,
    ],

    ["unkick by a player", unkick, player, lobby(), 403],
    ["unkick by the host", unkick, host, lobby(), null],
    [
      "unkick by the host of a listed lobby",
      unkick,
      host,
      lobby({ isListed: true }),
      403,
    ],
    ["unkick by edu admin", unkick, eduAdmin, lobby(), null],
    [
      "unkick by edu admin in a listed lobby",
      unkick,
      eduAdmin,
      lobby({ isListed: true }),
      null,
    ],
    [
      "unkick by edu admin on a public game",
      unkick,
      eduAdmin,
      lobby({ isPublic: true }),
      null,
    ],
    // admin_grant / admin_revive: edu-admin only, and only once the
    // simulation is running.
    ["grant by a player", grant, player, lobby({ hasStarted: true }), 403],
    ["grant by the host", grant, host, lobby({ hasStarted: true }), 403],
    ["grant by the admin bot", grant, bot, lobby({ hasStarted: true }), 403],
    [
      "grant by edu admin before start",
      grant,
      eduAdmin,
      lobby({ hasStarted: false }),
      409,
    ],
    ["grant by edu admin", grant, eduAdmin, lobby({ hasStarted: true }), null],
    [
      "grant by edu admin on a public game",
      grant,
      eduAdmin,
      lobby({ isPublic: true, hasStarted: true }),
      null,
    ],
    ["revive by a player", revive, player, lobby({ hasStarted: true }), 403],
    ["revive by the host", revive, host, lobby({ hasStarted: true }), 403],
    ["revive by the admin bot", revive, bot, lobby({ hasStarted: true }), 403],
    [
      "revive by edu admin before start",
      revive,
      eduAdmin,
      lobby({ hasStarted: false }),
      409,
    ],
    [
      "revive by edu admin",
      revive,
      eduAdmin,
      lobby({ hasStarted: true }),
      null,
    ],
    // admin_bibis_wrath: edu-admin only. Accepted in the lobby or mid-match
    // (lobby-fired intents queue into the first turn) — it's a UI overlay,
    // no simulation state is touched.
    ["bibi's wrath by a player", bibisWrath, player, lobby({ hasStarted: true }), 403],
    ["bibi's wrath by the host", bibisWrath, host, lobby({ hasStarted: true }), 403],
    ["bibi's wrath by the admin bot", bibisWrath, bot, lobby({ hasStarted: true }), 403],
    ["bibi's wrath by edu admin mid-match", bibisWrath, eduAdmin, lobby({ hasStarted: true }), null],
    ["bibi's wrath by edu admin in the lobby", bibisWrath, eduAdmin, lobby(), null],
    [
      "bibi's wrath by edu admin on a public game",
      bibisWrath,
      eduAdmin,
      lobby({ isPublic: true, hasStarted: true }),
      null,
    ],
    [
      "gameplay intent by edu admin is refused",
      spawn,
      eduAdmin,
      lobby(),
      400,
    ],

    ["config by a player", config({ bots: 1 }), player, lobby(), 403],
    [
      "config by an admin who is not the host",
      config({ bots: 1 }),
      admin,
      lobby(),
      403,
    ],
    ["config by the host", config({ bots: 1 }), host, lobby(), null],
    ["config by the bot", config({ bots: 1 }), bot, lobby(), null],
    ["config by edu admin", config({ bots: 1 }), eduAdmin, lobby(), null],
    [
      "config on a public game",
      config({ bots: 1 }),
      host,
      lobby({ isPublic: true }),
      403,
    ],
    [
      "config after the start",
      config({ bots: 1 }),
      host,
      lobby({ hasStarted: true }),
      409,
    ],
    [
      "config promoting the game to public",
      config({ gameType: GameType.Public }),
      host,
      lobby(),
      400,
    ],
    [
      "config enabling host cheats in a listed lobby",
      config({ hostCheats: { infiniteGold: true } }),
      host,
      lobby({ isListed: true }),
      409,
    ],
    [
      "config by the host in a listed lobby",
      config({ bots: 1 }),
      host,
      lobby({ isListed: true }),
      409,
    ],
    [
      "config by the bot in a listed lobby",
      config({ bots: 1 }),
      bot,
      lobby({ isListed: true }),
      null,
    ],
    [
      "config by edu admin in a listed lobby",
      config({ bots: 1 }),
      eduAdmin,
      lobby({ isListed: true }),
      null,
    ],
    [
      "config enabling host cheats in a bot's listed lobby",
      config({ hostCheats: { infiniteGold: true } }),
      bot,
      lobby({ isListed: true }),
      409,
    ],
    [
      "config enabling host cheats in edu admin's listed lobby",
      config({ hostCheats: { infiniteGold: true } }),
      eduAdmin,
      lobby({ isListed: true }),
      409,
    ],

    ["start timer by a player", timer, player, lobby(), 403],
    ["start timer by the host", timer, host, lobby(), null],
    ["start timer by the bot", timer, bot, lobby(), null],
    ["start timer by edu admin", timer, eduAdmin, lobby(), null],
    [
      "start timer by edu admin on a public game",
      timer,
      eduAdmin,
      lobby({ isPublic: true }),
      403,
    ],
    [
      "start timer on a public game",
      timer,
      host,
      lobby({ isPublic: true }),
      403,
    ],
    [
      "start timer after the start",
      timer,
      host,
      lobby({ hasStarted: true }),
      409,
    ],

    ["pause by a player", pause, player, lobby({ hasStarted: true }), 403],
    ["pause by the host", pause, host, lobby({ hasStarted: true }), null],
    [
      "pause by the host of a listed game",
      pause,
      host,
      lobby({ isListed: true, hasStarted: true }),
      403,
    ],
    [
      "pause by the bot in a listed game",
      pause,
      bot,
      lobby({ isListed: true, hasStarted: true }),
      null,
    ],
    [
      "pause by edu admin in a listed game",
      pause,
      eduAdmin,
      lobby({ isListed: true, hasStarted: true }),
      null,
    ],
    ["pause before the start", pause, host, lobby(), 409],

    ["gameplay by a player", spawn, player, lobby(), null],
    [
      "gameplay by a player in a public game",
      spawn,
      player,
      lobby({ isPublic: true }),
      null,
    ],
    ["gameplay by an admin", spawn, admin, lobby(), null],
    ["gameplay by the bot", spawn, bot, lobby(), 400],
    ["gameplay by edu admin", spawn, eduAdmin, lobby(), 400],
  ])("%s", (_name, intent, who, game, status) => {
    const outcome = authorizeIntent(intent, who, game);
    if (status === null) {
      expect(outcome).toBeNull();
    } else {
      expect(outcome).toMatchObject({ status, error: expect.any(String) });
    }
  });

  it("names the reason", () => {
    expect(authorizeIntent(kick, host, lobby({ isListed: true }))).toEqual({
      status: 403,
      error: "the host cannot kick players in a publicly listed lobby",
    });
  });
});
