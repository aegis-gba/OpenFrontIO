import { z } from "zod";
import { Execution, Game, Player, PlayerID } from "../game/Game";
import { GameID } from "../Schemas";
import { execSnapshotType } from "../snapshot/ExecutionSnapshot";
import type {
  ExecRecord,
  SnapshotReader,
} from "../snapshot/SnapshotContext";
import { PlayerExecution } from "./PlayerExecution";
import { SpawnExecution } from "./SpawnExecution";

// Edu-admin only execution: respawns a dead (0-tile) player at a fresh
// location using the standard spawn logic, then re-adds their PlayerExecution
// (the old one deactivated itself on death). Runs identically on every client
// via the turn queue. No-op if the target is unknown or still alive.
export class AdminReviveExecution implements Execution {
  private mg: Game;
  private target: Player | null = null;
  private active = true;

  constructor(
    private gameID: GameID,
    private targetID: PlayerID,
  ) {}

  init(mg: Game, ticks: number): void {
    this.mg = mg;
    if (!mg.hasPlayer(this.targetID)) {
      console.warn(`AdminReviveExecution: target ${this.targetID} not found`);
      this.active = false;
      return;
    }
    this.target = mg.player(this.targetID);
    if (this.target.isAlive()) {
      this.active = false;
      return;
    }
  }

  tick(ticks: number): void {
    this.active = false;
    if (!this.target) return;
    // fromIntent=false: this is an internal (admin) spawn, so it bypasses the
    // spawn-phase gate that restricts client spawn intents. forceRespawn=true
    // bypasses the random-spawn re-roll guard: the target is a dead player
    // being legitimately respawned mid-match.
    const spawn = new SpawnExecution(
      this.gameID,
      this.target.info(),
      undefined,
      false,
      true,
    );
    spawn.init(this.mg, ticks);
    spawn.tick(ticks);
    // The death path deactivated the player's PlayerExecution; bring them
    // back to life with a fresh one so troops/gold tick again.
    if (this.target.isAlive()) {
      this.mg.addExecution(new PlayerExecution(this.target));
    }
  }

  isActive(): boolean {
    return this.active;
  }

  activeDuringSpawnPhase(): boolean {
    return false;
  }

  snapshot(): ExecRecord {
    return AdminReviveExecutionSnapshot.write({
      active: this.active,
      initialized: this.mg !== undefined,
      gameID: this.gameID,
      targetID: this.targetID,
    });
  }

  restoreSnapshot(s: AdminReviveState, r: SnapshotReader): void {
    // Runs on Object.create(prototype): no constructor or field initializer
    // has run, so assign every field. If the execution was already init'd
    // before the snapshot, re-resolve the runtime refs; otherwise init()
    // runs later (restored executions land in unInitExecs) and sets them.
    this.active = s.active;
    this.gameID = s.gameID;
    this.targetID = s.targetID;
    if (s.initialized) {
      this.mg = r.game;
      this.target = r.game.hasPlayer(s.targetID)
        ? r.game.player(s.targetID)
        : null;
    } else {
      this.target = null;
    }
  }
}

const AdminReviveStateSchema = z.object({
  active: z.boolean(),
  initialized: z.boolean(),
  gameID: z.string(),
  targetID: z.string(),
});
type AdminReviveState = z.infer<typeof AdminReviveStateSchema>;

export const AdminReviveExecutionSnapshot = execSnapshotType({
  name: "AdminRevive",
  version: 1,
  schema: AdminReviveStateSchema,
  cls: () => AdminReviveExecution,
});
