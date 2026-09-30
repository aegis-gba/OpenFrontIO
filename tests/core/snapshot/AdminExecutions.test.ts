import { AdminBibisWrathExecution } from "../../../src/core/execution/AdminBibisWrathExecution";
import { AdminGrantExecution } from "../../../src/core/execution/AdminGrantExecution";
import { AdminReviveExecution } from "../../../src/core/execution/AdminReviveExecution";
import { SpawnExecution } from "../../../src/core/execution/SpawnExecution";
import {
  Game,
  Player,
  PlayerInfo,
  PlayerType,
} from "../../../src/core/game/Game";
import { GameUpdateType } from "../../../src/core/game/GameUpdates";
import { setup } from "../../util/Setup";
import { expectSnapshotRoundTrip } from "../../util/Snapshot";

const MAP = "plains";
const GAME_ID = "admin-snapshot-game";

function makePlayerInfo(id: string): PlayerInfo {
  return new PlayerInfo(`player-${id}`, PlayerType.Human, id, id);
}

async function setupSpawnedPlayer(
  id: string,
): Promise<{ game: Game; player: Player }> {
  const info = makePlayerInfo(id);
  const game = await setup(MAP, {});
  game.addPlayer(info);
  const spawn = new SpawnExecution(GAME_ID, info, undefined, false);
  spawn.init(game, 0);
  spawn.tick(0);
  const player = game.player(id);
  expect(player.isAlive()).toBe(true);
  return { game, player };
}

describe("admin execution snapshots", () => {
  test("grant: queued and initialized states round-trip", async () => {
    const { game, player } = await setupSpawnedPlayer("g1");
    const goldBefore = player.gold();

    // Queued but not yet init'd (sits in unInitExecs at snapshot time).
    game.addExecution(new AdminGrantExecution("g1", 500, 100));
    // Init'd but not yet ticked (sits in execs at snapshot time).
    const initd = new AdminGrantExecution("g1", 250, 50);
    game.addExecution(initd);
    game.executeNextTick(); // inits both; neither has ticked yet

    await expectSnapshotRoundTrip(game, MAP);

    // Both grants applied (plus 30 ticks of worker income on each side —
    // the round-trip helper already proved the two games stayed identical).
    expect(player.gold()).toBeGreaterThanOrEqual(goldBefore + BigInt(750));
  });

  test("revive: queued and initialized states round-trip", async () => {
    const { game, player } = await setupSpawnedPlayer("r1");
    Array.from(player.tiles()).forEach((t) => player.relinquish(t));
    expect(player.isAlive()).toBe(false);

    game.addExecution(new AdminReviveExecution(GAME_ID, "r1"));
    const initd = new AdminReviveExecution(GAME_ID, "r1");
    game.addExecution(initd);
    game.executeNextTick(); // inits both; neither has ticked yet

    await expectSnapshotRoundTrip(game, MAP);

    expect(player.isAlive()).toBe(true);
    expect(player.numTilesOwned()).toBeGreaterThan(0);
  });

  test("bibi's wrath: queued and initialized states round-trip", async () => {
    const { game } = await setupSpawnedPlayer("b1");

    game.addExecution(
      new AdminBibisWrathExecution("b1", "TheAdmin", "PlayerOne"),
    );
    const initd = new AdminBibisWrathExecution("b1", "TheAdmin", "PlayerOne");
    game.addExecution(initd);
    game.executeNextTick(); // inits both; neither has ticked yet

    const seen: string[] = [];
    const origAddUpdate = game.addUpdate.bind(game);
    game.addUpdate = ((update: any) => {
      if (update.type === GameUpdateType.BibisWrathEvent) {
        seen.push(`${update.adminName}>${update.targetName}`);
      }
      return origAddUpdate(update);
    }) as typeof game.addUpdate;

    await expectSnapshotRoundTrip(game, MAP);

    // Both executions emitted the splash update on the restored game.
    expect(seen).toEqual([
      "TheAdmin>PlayerOne",
      "TheAdmin>PlayerOne",
    ]);
  });

  test("bibi's wrath: NPC target round-trips (null targetID + isNPC)", async () => {
    const { game } = await setupSpawnedPlayer("b1");

    game.addExecution(
      new AdminBibisWrathExecution(null, "TheAdmin", "France", true),
    );
    const initd = new AdminBibisWrathExecution(
      null,
      "TheAdmin",
      "France",
      true,
    );
    game.addExecution(initd);
    game.executeNextTick(); // inits both; neither has ticked yet

    const seen: string[] = [];
    const origAddUpdate = game.addUpdate.bind(game);
    game.addUpdate = ((update: any) => {
      if (update.type === GameUpdateType.BibisWrathEvent) {
        seen.push(`${update.adminName}>${update.targetName}`);
      }
      return origAddUpdate(update);
    }) as typeof game.addUpdate;

    await expectSnapshotRoundTrip(game, MAP);

    expect(seen).toEqual(["TheAdmin>France", "TheAdmin>France"]);
  });
});
