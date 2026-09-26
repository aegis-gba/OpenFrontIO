/**
 * Self-host policy: everything in the store is free.
 *
 * This fork is deployed only to the private self-host (Render
 * `openfront-friends`), which has no payment rail and no official account
 * backend. Instead of selling cosmetics, every player — Pocket Edu accounts
 * and guests alike — is granted the full wildcard flare set, so the client
 * relationship helpers resolve every catalog item as "owned" and the
 * worker's PrivilegeCheckerImpl allows every cosmetic ref at join.
 *
 * The three namespaces in identityNamespaces.ts are unaffected: this grants
 * cosmetics, not identity. A guest still cannot reclaim an account's
 * player/lobby.
 */
export const SELFHOST_FREE_FLARES: readonly string[] = [
  "pattern:*",
  "flag:*",
  "crown:*",
  "skin:*",
  "effect:*",
];

/**
 * Base URL the game server's PrivilegeRefresher fetches the cosmetics
 * catalog and reserved clan tags from. The adapter (render-start.mjs) serves
 * the vendored catalog at /cosmetics.json on its public port and publishes
 * this address as SELFHOST_CATALOG_BASE; the default jwtIssuer() points at a
 * dead localhost:8787 on the self-host, so it must not be used here.
 */
export function selfhostCatalogBase(): string {
  const fromEnv = process.env.SELFHOST_CATALOG_BASE;
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  return `http://127.0.0.1:${process.env.PORT ?? "10000"}`;
}
