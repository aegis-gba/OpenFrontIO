import { expect, it } from "vitest";
import { AdminReviveExecution } from "../../../src/core/execution/AdminReviveExecution";
import { SpawnExecution } from "../../../src/core/execution/SpawnExecution";
import {
  Game,
  Player,
  PlayerInfo,
  PlayerType,
} from "../../../src/core/game/Game";
import { setup } from "../../util/Setup";

const GAME_ID = "revive-game";

function makePlayerInfo(id: string): PlayerInfo {
  // Production GameServer stamps PlayerInfo with id === clientID.
  return new PlayerInfo(`player-${id}`, PlayerType.Human, id, id);
}

async function setupSpawnedGame(
  randomSpawn: boolean,
  id: string,
): Promise<{ game: Game; player: Player }> {
  const info = makePlayerInfo(id);
  const game = await setup("plains", { randomSpawn }, [info]);
  game.addPlayer(info);
  const spawn = new SpawnExecution(GAME_ID, info, undefined, false);
  spawn.init(game, 0);
  spawn.tick(0);
  const player = game.player(id);
  expect(player.isAlive()).toBe(true);
  return { game, player };
}

function kill(player: Player): void {
  Array.from(player.tiles()).forEach((t) => player.relinquish(t));
  expect(player.isAlive()).toBe(false);
}

function revive(game: Game, targetID: string): AdminReviveExecution {
  const exec = new AdminReviveExecution(GAME_ID, targetID);
  exec.init(game, 0);
  exec.tick(0);
  return exec;
}

describe("AdminReviveExecution", () => {
  it("revives a dead player in a normal game", async () => {
    const { game, player } = await setupSpawnedGame(false, "c1");
    kill(player);

    const exec = revive(game, "c1");
    expect(exec.isActive()).toBe(false);
    expect(player.isAlive()).toBe(true);
    expect(player.numTilesOwned()).toBeGreaterThan(0);
    // A fresh PlayerExecution drives the revived player's economy: run a
    // few ticks and confirm gold accrues again.
    const goldBefore = player.gold();
    for (let i = 0; i < 10; i++) game.executeNextTick();
    expect(player.gold()).toBeGreaterThan(goldBefore);
  });

  it("revives a dead player in a random-spawn game", async () => {
    const { game, player } = await setupSpawnedGame(true, "c2");
    kill(player);

    revive(game, "c2");
    expect(player.isAlive()).toBe(true);
    expect(player.numTilesOwned()).toBeGreaterThan(0);
    const goldBefore = player.gold();
    for (let i = 0; i < 10; i++) game.executeNextTick();
    expect(player.gold()).toBeGreaterThan(goldBefore);
  });

  it("leaves an alive player unchanged", async () => {
    const { game, player } = await setupSpawnedGame(false, "c3");
    const tilesBefore = player.numTilesOwned();

    const exec = new AdminReviveExecution(GAME_ID, "c3");
    exec.init(game, 0);
    expect(exec.isActive()).toBe(false);
    exec.tick(0);

    expect(player.numTilesOwned()).toBe(tilesBefore);
  });

  it("is a no-op for an unknown player", async () => {
    const { game } = await setupSpawnedGame(false, "c4");

    const exec = new AdminReviveExecution(GAME_ID, "nobody");
    exec.init(game, 0);
    expect(exec.isActive()).toBe(false);
    exec.tick(0);
    // Nothing changed: no new executions were queued for the ghost.
    expect(game.hasPlayer("nobody")).toBe(false);
  });

  it("respawns deterministically across identical runs", async () => {
    // SpawnExecution seeds its RNG from playerInfo.id + gameID, so two
    // identical revives must land on the same tile (snapshot/replay safety).
    const { game: gameA, player: playerA } = await setupSpawnedGame(
      true,
      "c5",
    );
    const { game: gameB, player: playerB } = await setupSpawnedGame(
      true,
      "c5",
    );
    kill(playerA);
    kill(playerB);

    revive(gameA, "c5");
    revive(gameB, "c5");

    expect(playerA.isAlive()).toBe(true);
    expect(playerB.isAlive()).toBe(true);
    expect(playerA.spawnTile()).toBe(playerB.spawnTile());
    expect(playerA.numTilesOwned()).toBe(playerB.numTilesOwned());
  });
});
