import type { ClientPlatform } from "../core/Schemas";
import { crazyGamesSDK } from "./CrazyGamesSDK";
import { isDesktopShell } from "./DesktopShell";

// The desktop shell is only distributed through Steam, so the shell itself
// (not a working Steam client, which may be absent) is the signal.
export function clientPlatform(): ClientPlatform {
  if (isDesktopShell()) return "steam";
  if (typeof window !== "undefined" && crazyGamesSDK.isOnCrazyGames()) {
    return "crazygames";
  }
  return "web";
}

/**
 * Heuristic for low-end devices (Chromebooks, older phones): few logical CPU
 * cores. Used to default to the Performance graphics preset and to cap the
 * WebGL backing-store resolution. An unknown core count is not weak — never
 * degrade when the API is missing.
 */
export function isWeakDevice(): boolean {
  if (typeof navigator === "undefined") return false;
  const cores = navigator.hardwareConcurrency ?? 8;
  return cores <= 4;
}
