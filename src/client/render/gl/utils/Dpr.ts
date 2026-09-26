import { isWeakDevice } from "../../../ClientPlatform";

/**
 * Device-pixel-ratio used by the WebGL renderer for its backing store and all
 * screen↔world math. Capped at 2 to avoid rendering at 3x on very high-DPI
 * (mobile) displays, which costs ~9x the fragment work of 1x for a marginal
 * visual gain over 2x.
 *
 * On weak devices (few CPU cores: Chromebooks, old phones) the cap drops to
 * 1 — DPR 2 quadruples fragment work, the single biggest cost on integrated
 * GPUs, and the game stays sharp enough at 1x on those screens.
 *
 * Every renderer call site that previously read `window.devicePixelRatio`
 * must go through this so the canvas size, camera math, and text scaling stay
 * on the same coordinate system.
 */
export function renderDpr(): number {
  const cap = isWeakDevice() ? 1 : 2;
  return Math.min(window.devicePixelRatio || cap, cap);
}
