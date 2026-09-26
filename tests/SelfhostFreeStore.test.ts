import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isWeakDevice } from "../src/client/ClientPlatform";
import {
  cosmeticPackRelationship,
  cosmeticRelationship,
  crownRelationship,
  effectRelationship,
  flagRelationship,
  ownedPackItems,
  patternRelationship,
  resolveCosmetics,
  skinRelationship,
} from "../src/client/Cosmetics";
import {
  BUILTIN_PRESETS,
  migrateLegacyGraphicsSettings,
} from "../src/client/GraphicsPresets";
import { GraphicsOverridesSchema } from "../src/client/render/gl/GraphicsOverrides";
import { applyGraphicsOverrides } from "../src/client/render/gl/RenderOverrides";
import { createRenderSettings } from "../src/client/render/gl/RenderSettings";
import { renderDpr } from "../src/client/render/gl/utils/Dpr";
import { UserMeResponse } from "../src/core/ApiSchemas";
import { CosmeticPack, Cosmetics } from "../src/core/CosmeticSchemas";
import {
  GRAPHICS_KEY,
  GRAPHICS_PRESETS_KEY,
  UserSettings,
} from "../src/core/game/UserSettings";
import {
  SELFHOST_FREE_FLARES,
  selfhostCatalogBase,
} from "../src/server/selfhost";

function makeUserMe(flares: string[]): UserMeResponse {
  return { player: { flares } } as unknown as UserMeResponse;
}

function makeCosmetics(overrides: Partial<Cosmetics> = {}): Cosmetics {
  return {
    patterns: {},
    flags: {},
    colorPalettes: {},
    ...overrides,
  } as Cosmetics;
}

function setHardwareConcurrency(cores: number) {
  Object.defineProperty(window.navigator, "hardwareConcurrency", {
    value: cores,
    configurable: true,
  });
}

function resetUserSettingsState() {
  localStorage.clear();
  const statics = UserSettings as unknown as {
    cache: Map<string, string | null>;
    playerId: string | null;
  };
  statics.cache.clear();
  statics.playerId = null;
}

describe("selfhost free-store policy", () => {
  it("grants exactly the five wildcard flares", () => {
    expect([...SELFHOST_FREE_FLARES].sort()).toEqual(
      ["crown:*", "effect:*", "flag:*", "pattern:*", "skin:*"].sort(),
    );
  });

  it("catalog base follows SELFHOST_CATALOG_BASE, else local port", () => {
    const saved = process.env.SELFHOST_CATALOG_BASE;
    try {
      process.env.SELFHOST_CATALOG_BASE = "http://127.0.0.1:1234";
      expect(selfhostCatalogBase()).toBe("http://127.0.0.1:1234");
      delete process.env.SELFHOST_CATALOG_BASE;
      delete process.env.PORT;
      expect(selfhostCatalogBase()).toBe("http://127.0.0.1:10000");
    } finally {
      if (saved === undefined) delete process.env.SELFHOST_CATALOG_BASE;
      else process.env.SELFHOST_CATALOG_BASE = saved;
    }
  });
});

describe("guest cosmetics ownership (self-host: everything is free)", () => {
  const opts = {
    wildcardFlare: "flag:*",
    requiredFlare: "flag:cool",
    priceSoft: undefined,
    priceHard: undefined,
    affiliateCode: null,
    itemAffiliateCode: null,
  };

  it("cosmeticRelationship returns owned for guests", () => {
    expect(cosmeticRelationship(opts, false)).toBe("owned");
  });

  it("patternRelationship returns owned for guests (all palette states)", () => {
    const pattern = { name: "camo" } as never;
    expect(patternRelationship(pattern, null, false, null)).toBe("owned");
    expect(
      patternRelationship(
        pattern,
        { name: "red", isArchived: true },
        false,
        null,
      ),
    ).toBe("owned");
    expect(patternRelationship(pattern, { name: "red" }, false, null)).toBe(
      "owned",
    );
  });

  it("flag/crown/skin/effect relationships return owned for guests", () => {
    expect(flagRelationship({ name: "cool" } as never, false, null)).toBe(
      "owned",
    );
    expect(crownRelationship({ name: "gold" } as never, false, null)).toBe(
      "owned",
    );
    expect(skinRelationship({ name: "lava" } as never, false, null)).toBe(
      "owned",
    );
    expect(effectRelationship({ name: "sparkle" } as never, false, null)).toBe(
      "owned",
    );
  });

  it("accounts with the wildcard grant own everything too", () => {
    const me = makeUserMe([...SELFHOST_FREE_FLARES]);
    expect(cosmeticRelationship(opts, me)).toBe("owned");
    expect(flagRelationship({ name: "cool" } as never, me, null)).toBe("owned");
  });

  it("ownedPackItems returns every item for guests; pack is owned", () => {
    const pack = {
      items: [
        { type: "flag", name: "a" },
        { type: "skin", name: "b" },
      ],
    } as unknown as CosmeticPack;
    expect(ownedPackItems(pack, false)).toHaveLength(2);
    expect(cosmeticPackRelationship(pack, false, null)).toBe("owned");
  });

  it("currency packs resolve as blocked (no payment rail on self-host)", () => {
    const cosmetics = makeCosmetics({
      currencyPacks: {
        small: {
          name: "small",
          displayName: "Small",
          rarity: "common",
          currency: "hard",
          amount: 100,
          bonusAmount: 0,
          product: { productId: "p", priceId: "pr", price: "$0.99" },
        },
      },
    });
    const resolved = resolveCosmetics(cosmetics, false, null);
    const pack = resolved.find((r) => r.type === "pack");
    expect(pack).toBeDefined();
    expect(pack!.relationship).toBe("blocked");
  });
});

describe("audio defaults (self-host: start audible on web)", () => {
  beforeEach(resetUserSettingsState);
  afterEach(resetUserSettingsState);

  it("fresh web player gets an audible master default", () => {
    const s = new UserSettings();
    expect(s.audioVolume("master")).toBeCloseTo(0.9);
  });

  it("a deliberately stored master of 0 is still respected", () => {
    const s = new UserSettings();
    s.setAudioVolume("master", 0);
    expect(new UserSettings().audioVolume("master")).toBe(0);
  });
});

describe("performance graphics preset", () => {
  it("exists with schema-valid overrides that disable the expensive passes", () => {
    const perf = BUILTIN_PRESETS.find(
      (p) => p.nameKey === "graphics_setting.preset_performance",
    );
    expect(perf).toBeDefined();
    const parsed = GraphicsOverridesSchema.safeParse(perf!.overrides);
    expect(parsed.success, `${parsed.error}`).toBe(true);
    expect(perf!.overrides.passEnabled).toMatchObject({
      fx: false,
      fallout: false,
    });
    expect(perf!.overrides.smallPlayerGlow).toMatchObject({ strength: 0 });
  });

  it("disables the fx and fallout passes when applied to render settings", () => {
    const perf = BUILTIN_PRESETS.find(
      (p) => p.nameKey === "graphics_setting.preset_performance",
    )!;
    const settings = createRenderSettings();
    applyGraphicsOverrides(
      settings,
      GraphicsOverridesSchema.parse(perf.overrides),
    );
    expect(settings.passEnabled.fx).toBe(false);
    expect(settings.passEnabled.falloutBloom).toBe(false);
    expect(settings.passEnabled.falloutLight).toBe(false);
  });
});

describe("isWeakDevice", () => {
  it("treats 4 or fewer cores as weak", () => {
    setHardwareConcurrency(4);
    expect(isWeakDevice()).toBe(true);
    setHardwareConcurrency(2);
    expect(isWeakDevice()).toBe(true);
  });

  it("treats more than 4 cores as not weak", () => {
    setHardwareConcurrency(8);
    expect(isWeakDevice()).toBe(false);
  });
});

describe("weak-device graphics migration", () => {
  const userSettings = new UserSettings();

  beforeEach(() => {
    userSettings.removeCached(GRAPHICS_KEY);
    userSettings.removeCached(GRAPHICS_PRESETS_KEY);
  });

  it("fresh weak-device player starts on the Performance preset", () => {
    setHardwareConcurrency(4);
    migrateLegacyGraphicsSettings(userSettings);
    const perf = BUILTIN_PRESETS.find(
      (p) => p.nameKey === "graphics_setting.preset_performance",
    )!;
    expect(userSettings.graphicsOverrides()).toEqual(perf.overrides);
  });

  it("does not overwrite custom settings on a weak device", () => {
    setHardwareConcurrency(4);
    userSettings.setGraphicsOverrides({ name: { nameScaleFactor: 2 } });
    migrateLegacyGraphicsSettings(userSettings);
    expect(userSettings.graphicsOverrides()).toEqual({
      name: { nameScaleFactor: 2 },
    });
  });

  it("fresh strong-device player keeps the Default (empty) overrides", () => {
    setHardwareConcurrency(8);
    migrateLegacyGraphicsSettings(userSettings);
    expect(userSettings.graphicsOverrides()).toEqual({});
  });
});

describe("renderDpr", () => {
  const realDpr = window.devicePixelRatio;

  afterEach(() => {
    Object.defineProperty(window, "devicePixelRatio", {
      value: realDpr,
      configurable: true,
    });
  });

  it("caps at 1 on weak devices even at DPR 2", () => {
    setHardwareConcurrency(4);
    Object.defineProperty(window, "devicePixelRatio", {
      value: 2,
      configurable: true,
    });
    expect(renderDpr()).toBe(1);
  });

  it("caps at 2 on strong devices", () => {
    setHardwareConcurrency(8);
    Object.defineProperty(window, "devicePixelRatio", {
      value: 3,
      configurable: true,
    });
    expect(renderDpr()).toBe(2);
  });
});
