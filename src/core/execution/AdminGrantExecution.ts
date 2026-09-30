import { z } from "zod";
import { Execution, Game, Player, PlayerID } from "../game/Game";
import { execSnapshotType } from "../snapshot/ExecutionSnapshot";
import type {
  ExecRecord,
  SnapshotReader,
} from "../snapshot/SnapshotContext";

// Edu-admin only execution: grants (or removes, if negative) gold and troops
// to a target player. Runs identically on every client via the turn queue, so
// all simulations stay in sync. No-op if the target player is unknown.
export class AdminGrantExecution implements Execution {
  private mg: Game;
  private target: Player | null = null;
  private active = true;

  constructor(
    private targetID: PlayerID,
    private goldDelta: number | null,
    private troopsDelta: number | null,
  ) {}

  init(mg: Game, ticks: number): void {
    this.mg = mg;
    if (!mg.hasPlayer(this.targetID)) {
      console.warn(`AdminGrantExecution: target ${this.targetID} not found`);
      this.active = false;
      return;
    }
    this.target = mg.player(this.targetID);
  }

  tick(ticks: number): void {
    this.active = false;
    if (!this.target) return;
    if (this.goldDelta !== null && this.goldDelta !== 0) {
      if (this.goldDelta > 0) {
        this.target.addGold(BigInt(this.goldDelta));
      } else {
        this.target.removeGold(BigInt(-this.goldDelta));
      }
    }
    if (this.troopsDelta !== null && this.troopsDelta !== 0) {
      if (this.troopsDelta > 0) {
        this.target.addTroops(this.troopsDelta);
      } else {
        this.target.removeTroops(-this.troopsDelta);
      }
    }
  }

  isActive(): boolean {
    return this.active;
  }

  activeDuringSpawnPhase(): boolean {
    return false;
  }

  snapshot(): ExecRecord {
    return AdminGrantExecutionSnapshot.write({
      active: this.active,
      initialized: this.mg !== undefined,
      targetID: this.targetID,
      goldDelta: this.goldDelta,
      troopsDelta: this.troopsDelta,
    });
  }

  restoreSnapshot(s: AdminGrantState, r: SnapshotReader): void {
    // Runs on Object.create(prototype): no constructor or field initializer
    // has run, so assign every field. If the execution was already init'd
    // before the snapshot, re-resolve the runtime refs; otherwise init()
    // runs later (restored executions land in unInitExecs) and sets them.
    this.active = s.active;
    this.targetID = s.targetID;
    this.goldDelta = s.goldDelta;
    this.troopsDelta = s.troopsDelta;
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

const AdminGrantStateSchema = z.object({
  active: z.boolean(),
  initialized: z.boolean(),
  targetID: z.string(),
  goldDelta: z.number().nullable(),
  troopsDelta: z.number().nullable(),
});
type AdminGrantState = z.infer<typeof AdminGrantStateSchema>;

export const AdminGrantExecutionSnapshot = execSnapshotType({
  name: "AdminGrant",
  version: 1,
  schema: AdminGrantStateSchema,
  cls: () => AdminGrantExecution,
});
