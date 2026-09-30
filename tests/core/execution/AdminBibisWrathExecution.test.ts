import { expect, it, vi } from "vitest";
import { AdminBibisWrathExecution } from "../../../src/core/execution/AdminBibisWrathExecution";
import { PlayerInfo, PlayerType } from "../../../src/core/game/Game";
import { GameUpdateType } from "../../../src/core/game/GameUpdates";
import { setup } from "../../util/Setup";

describe("AdminBibisWrathExecution", () => {
  it("emits a BibisWrathEvent update with the admin and target names", async () => {
    // In production GameServer stamps PlayerInfo with id === clientID.
    const players = [new PlayerInfo("boss", PlayerType.Human, "c1", "c1")];
    const game = await setup("plains", {}, players);
    game.addPlayer(players[0]);
    const addUpdate = vi.spyOn(game, "addUpdate");

    const exec = new AdminBibisWrathExecution("c1", "TheAdmin", "PlayerOne");
    exec.init(game, 0);
    expect(exec.isActive()).toBe(true);
    exec.tick(0);
    expect(exec.isActive()).toBe(false);

    expect(addUpdate).toHaveBeenCalledWith({
      type: GameUpdateType.BibisWrathEvent,
      adminName: "TheAdmin",
      targetName: "PlayerOne",
    });
  });

  it("is a no-op when the target player is unknown", async () => {
    const players = [new PlayerInfo("boss", PlayerType.Human, "c1", "c1")];
    const game = await setup("plains", {}, players);
    game.addPlayer(players[0]);
    const addUpdate = vi.spyOn(game, "addUpdate");

    const exec = new AdminBibisWrathExecution("nobody", "TheAdmin", "Ghost");
    exec.init(game, 0);
    expect(exec.isActive()).toBe(false);
    expect(addUpdate).not.toHaveBeenCalled();
  });

  it("fires for an NPC target without a simulation player", async () => {
    // Bots live only in the simulation; the server can't resolve their IDs,
    // so an NPC target carries targetID null + isNPC and skips the
    // hasPlayer check — the overlay is cosmetic.
    const players = [new PlayerInfo("boss", PlayerType.Human, "c1", "c1")];
    const game = await setup("plains", {}, players);
    game.addPlayer(players[0]);
    const addUpdate = vi.spyOn(game, "addUpdate");

    const exec = new AdminBibisWrathExecution(
      null,
      "TheAdmin",
      "France",
      true,
    );
    exec.init(game, 0);
    expect(exec.isActive()).toBe(true);
    exec.tick(0);
    expect(addUpdate).toHaveBeenCalledWith({
      type: GameUpdateType.BibisWrathEvent,
      adminName: "TheAdmin",
      targetName: "France",
    });
  });
});
