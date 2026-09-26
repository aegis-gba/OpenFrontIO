// Post-build step for STATIC hosting (Netlify) of the OpenFront client.
//
// On the Render deployment, render-start.mjs patches every served HTML page:
//   1. seeds localStorage "apiHost" so the client's API calls reach the game
//      backend instead of the unreachable dev default,
//   2. hides the "Buy OpenFront on Steam" promo units,
//   3. removes the third-party Playwire ad tag.
//
// A static host has no such adapter, so apply the same patches directly to
// the freshly rendered static/index.html. Run AFTER
// `node --import tsx src/server/RenderStaticIndex.ts` has rendered the page.
import fs from "node:fs";

const BACKEND_ORIGIN = "https://openfront-friends.onrender.com";
const PATH = "static/index.html";

let html = fs.readFileSync(PATH, "utf8");

const inject =
  `<script>try{localStorage.setItem("apiHost","${BACKEND_ORIGIN}")}catch(e){}</script>` +
  `<style>.steam-wishlist-frame,steam-wishlist,steam-wishlist-button,` +
  `div:not(#page-play):has(>steam-wishlist),` +
  `div:not(#page-play):has(>steam-wishlist-button)` +
  `{display:none!important}</style>`;

if (!html.includes('localStorage.setItem("apiHost"')) {
  const replaced = html.replace(/<head[^>]*>/i, (m) => m + inject);
  html = replaced === html ? inject + html : replaced;
}

// Drop the official site's Playwire ad tag; ads are not served on a self-host.
html = html.replace(
  /<script[^>]*cdn\.intergient\.com[^>]*>\s*<\/script>/gi,
  "<!-- ads disabled on this self-host -->",
);

fs.writeFileSync(PATH, html);
console.log(`netlify-static-postbuild: patched ${PATH} (${html.length} bytes)`);
