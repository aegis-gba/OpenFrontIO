import { z } from "zod";
import { Execution, Game, PlayerID } from "../game/Game";
import { GameUpdateType } from "../game/GameUpdates";
import { execSnapshotType } from "../snapshot/ExecutionSnapshot";
import type {
  ExecRecord,
  SnapshotReader,
} from "../snapshot/SnapshotContext";

// Edu-admin only execution: "Bibi's Wrath". Emits a BibisWrathEvent update
// carrying the admin name (left box) and the target player's name (right
// box); the client UI renders the fullscreen VS splash for 5 seconds. Runs
// identically on every client via the turn queue so all screens show it on
// the same tick. NPC targets (isNPC) skip the player-exists check: bots live
// only in the simulation, so the server can't resolve their IDs, and the
// overlay is cosmetic — it needs only the display names.
export class AdminBibisWrathExecution implements Execution {
  private mg: Game;
  private active = true;

  constructor(
    private targetID: PlayerID | null,
    private adminName: string,
    private targetName: string,
    private isNPC: boolean = false,
  ) {}

  init(mg: Game, ticks: number): void {
    this.mg = mg;
    if (
      !this.isNPC &&
      (this.targetID === null || !mg.hasPlayer(this.targetID))
    ) {
      console.warn(
        `AdminBibisWrathExecution: target ${this.targetID} not found`,
      );
      this.active = false;
    }
  }

  tick(ticks: number): void {
    this.active = false;
    this.mg.addUpdate({
      type: GameUpdateType.BibisWrathEvent,
      adminName: this.adminName,
      targetName: this.targetName,
    });
  }

  isActive(): boolean {
    return this.active;
  }

  activeDuringSpawnPhase(): boolean {
    return false;
  }

  snapshot(): ExecRecord {
    return AdminBibisWrathExecutionSnapshot.write({
      active: this.active,
      initialized: this.mg !== undefined,
      targetID: this.targetID,
      adminName: this.adminName,
      targetName: this.targetName,
      isNPC: this.isNPC,
    });
  }

  restoreSnapshot(s: AdminBibisWrathState, r: SnapshotReader): void {
    // Runs on Object.create(prototype): no constructor or field initializer
    // has run, so assign every field. If the execution was already init'd
    // before the snapshot, re-resolve the game ref; otherwise init() runs
    // later (restored executions land in unInitExecs) and sets it.
    this.active = s.active;
    this.targetID = s.targetID;
    this.adminName = s.adminName;
    this.targetName = s.targetName;
    this.isNPC = s.isNPC;
    if (s.initialized) {
      this.mg = r.game;
    }
  }
}

const AdminBibisWrathStateSchema = z.object({
  active: z.boolean(),
  initialized: z.boolean(),
  targetID: z.string().nullable(),
  adminName: z.string(),
  targetName: z.string(),
  // Optional with default so pre-NPC snapshots (which lack the field)
  // still restore without a version bump or migration.
  isNPC: z.boolean().optional().default(false),
});
type AdminBibisWrathState = z.infer<typeof AdminBibisWrathStateSchema>;

export const AdminBibisWrathExecutionSnapshot = execSnapshotType({
  name: "AdminBibisWrath",
  version: 1,
  schema: AdminBibisWrathStateSchema,
  cls: () => AdminBibisWrathExecution,
});
