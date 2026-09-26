import { jwtVerify } from "jose";
import { z } from "zod";
import {
  TokenPayload,
  TokenPayloadSchema,
  UserMeResponse,
  UserMeResponseSchema,
} from "../core/ApiSchemas";
import { GameEnv } from "../core/configuration/Config";
import { PersistentIdSchema } from "../core/Schemas";
import { ServerEnv } from "./ServerEnv";
import { logger } from "./Logger";
import {
  buildPocketEduUserMe,
  isPocketEduToken,
  verifyPocketEduToken,
} from "./pocketEduAuth";

const log = logger.child({ comp: "jwt" });

type TokenVerificationResult =
  | {
      type: "success";
      persistentId: string;
      claims: TokenPayload | null;
      // Who vouched for this identity: a dev-mode guest token, the
      // deployment's own issuer, or a verified Pocket Edu account.
      provider: "guest" | "local" | "pocketedu";
      // Signed display name; only present for verified Pocket Edu accounts.
      displayName?: string;
    }
  | { type: "error"; message: string };

export async function verifyClientToken(
  token: string,
): Promise<TokenVerificationResult> {
  if (PersistentIdSchema.safeParse(token).success) {
    if (ServerEnv.env() === GameEnv.Dev) {
      // Guest identity. Pocket Edu account identities are HMAC-derived
      // (see pocketEduAuth.ts) and can never equal a guest-supplied UUID,
      // so presenting an account's subject UUID here yields a *different*
      // identity — it cannot impersonate the account.
      return {
        type: "success",
        persistentId: token,
        claims: null,
        provider: "guest",
      };
    } else {
      return {
        type: "error",
        message: "persistent ID not allowed in production",
      };
    }
  }
  // A token that *claims* Pocket Edu as its issuer is routed to the Pocket
  // Edu verifier and must verify there. Failure is final: it is never
  // retried against the local issuer and never downgraded to a guest.
  if (isPocketEduToken(token)) {
    const pe = await verifyPocketEduToken(token);
    if (!pe.ok) {
      log.warn(`Pocket Edu token rejected: ${pe.reason}`);
      return { type: "error", message: `Pocket Edu token rejected` };
    }
    return {
      type: "success",
      persistentId: pe.identity.persistentId,
      claims: pe.identity.claims,
      provider: "pocketedu",
      displayName: pe.identity.displayName,
    };
  }
  try {
    const issuer = ServerEnv.jwtIssuer();
    const audience = ServerEnv.jwtAudience();
    const key = await ServerEnv.jwkPublicKey();
    const { payload } = await jwtVerify(token, key, {
      algorithms: ["EdDSA"],
      issuer,
      audience,
    });
    const result = TokenPayloadSchema.safeParse(payload);
    if (!result.success) {
      return {
        type: "error",
        message: z.prettifyError(result.error),
      };
    }
    const claims = result.data;
    const persistentId = claims.sub;
    return { type: "success", persistentId, claims, provider: "local" };
  } catch (e) {
    const message =
      e instanceof Error
        ? e.message
        : typeof e === "string"
          ? e
          : "An unknown error occurred";

    return { type: "error", message };
  }
}

export async function getUserMe(
  token: string,
): Promise<
  | { type: "success"; response: UserMeResponse }
  | { type: "error"; message: string }
> {
  // Pocket Edu account profiles are answered locally and honestly: this
  // self-host has no store, subscriptions, rankings or achievements to
  // report. The upstream account API does not exist here, so a Pocket Edu
  // token must never be forwarded to it.
  if (isPocketEduToken(token)) {
    const pe = await verifyPocketEduToken(token);
    if (!pe.ok) {
      log.warn(`Pocket Edu token rejected: ${pe.reason}`);
      return { type: "error", message: "Pocket Edu token rejected" };
    }
    const response = buildPocketEduUserMe(pe.identity);
    if (!response) {
      return { type: "error", message: "Failed to build account profile" };
    }
    return { type: "success", response };
  }
  try {
    // Get the user object
    const response = await fetch(ServerEnv.jwtIssuer() + "/users/@me", {
      headers: {
        authorization: `Bearer ${token}`,
        "x-api-key": ServerEnv.apiKey(),
      },
    });
    if (response.status !== 200) {
      return {
        type: "error",
        message: `Failed to fetch user me: ${response.statusText}`,
      };
    }
    const body = await response.json();
    const result = UserMeResponseSchema.safeParse(body);
    if (!result.success) {
      return {
        type: "error",
        message: `Invalid response: ${z.prettifyError(result.error)}`,
      };
    }
    return { type: "success", response: result.data };
  } catch (e) {
    return {
      type: "error",
      message: `Failed to fetch user me: ${e}`,
    };
  }
}
