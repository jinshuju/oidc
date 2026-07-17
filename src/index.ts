import {
  UnauthenticatedError,
  extractBearerToken,
  type AuthFn,
} from "eve/channels/auth";

const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const ATTRIBUTE_KEYS = ["email", "groups", "locale", "name", "picture", "preferred_username", "roles"] as const;

export type JinshujuOidcEnvironment = Readonly<Record<string, string | undefined>>;

export type JinshujuOidcOptions = {
  issuer?: string;
  userInfoUrl?: string;
  discoveryUrl?: string;
  timeoutMs?: number;
  env?: JinshujuOidcEnvironment;
  fetch?: typeof globalThis.fetch;
  /** Intended for local integration tests only. Production endpoints must use HTTPS. */
  allowInsecureHttp?: boolean;
};

type ResolvedOptions = {
  issuer: string;
  userInfoUrl?: string;
  discoveryUrl: string;
  timeoutMs: number;
  fetch: typeof globalThis.fetch;
  allowInsecureHttp: boolean;
};

type UserInfo = Record<string, unknown> & { sub: string };

/**
 * Creates an Eve 0.24.6-compatible route authenticator for Jinshuju OIDC.
 *
 * Configuration is resolved when this factory is called, not while the module
 * is imported or built. Opaque bearer tokens are verified through UserInfo.
 */
export function jinshujuOidc(options: JinshujuOidcOptions = {}): AuthFn<Request> {
  const resolved = resolveOptions(options);
  let discoveredUserInfoUrl: Promise<string> | undefined;

  const resolveUserInfoUrl = async (): Promise<string> => {
    if (resolved.userInfoUrl) return resolved.userInfoUrl;
    discoveredUserInfoUrl ??= discoverUserInfoUrl(resolved).catch((error: unknown) => {
      discoveredUserInfoUrl = undefined;
      throw error;
    });
    return discoveredUserInfoUrl;
  };

  return async (request) => {
    const token = extractBearerToken(request.headers.get("authorization"));
    if (!token) return null;

    let userInfo: UserInfo | null;
    try {
      userInfo = await fetchUserInfo(token, await resolveUserInfoUrl(), resolved);
    } catch {
      throw new UnauthenticatedError({
        code: "jinshuju_oidc_provider_unavailable",
        message: "Authorization could not be verified.",
        challenges: [{ scheme: "Bearer" }],
      });
    }
    if (!userInfo) return null;

    return {
      attributes: projectAttributes(userInfo),
      authenticator: "jinshuju-oidc",
      issuer: resolved.issuer,
      principalId: `${resolved.issuer}:${userInfo.sub}`,
      principalType: "user",
      subject: userInfo.sub,
    };
  };
}

function resolveOptions(options: JinshujuOidcOptions): ResolvedOptions {
  const env = options.env ?? process.env;
  const allowInsecureHttp = options.allowInsecureHttp ?? false;
  const issuerInput = options.issuer ?? env.JINSHUJU_OIDC_ISSUER;
  if (!issuerInput?.trim()) throw new Error("JINSHUJU_OIDC_ISSUER is required.");
  const issuer = normalizeEndpoint(issuerInput, "OIDC issuer", allowInsecureHttp, true);
  const userInfoInput = options.userInfoUrl ?? env.JINSHUJU_OIDC_USERINFO_URL;
  const discoveryInput = options.discoveryUrl ?? env.JINSHUJU_OIDC_DISCOVERY_URL
    ?? `${issuer}/.well-known/openid-configuration`;
  const timeoutInput = options.timeoutMs ?? parseTimeout(env.JINSHUJU_OIDC_TIMEOUT_MS);

  if (!Number.isSafeInteger(timeoutInput) || timeoutInput < 100 || timeoutInput > 60_000) {
    throw new Error("JINSHUJU_OIDC_TIMEOUT_MS must be an integer between 100 and 60000.");
  }

  return {
    issuer,
    ...(userInfoInput ? { userInfoUrl: normalizeEndpoint(userInfoInput, "OIDC UserInfo endpoint", allowInsecureHttp) } : {}),
    discoveryUrl: normalizeEndpoint(discoveryInput, "OIDC discovery endpoint", allowInsecureHttp),
    timeoutMs: timeoutInput,
    fetch: options.fetch ?? globalThis.fetch,
    allowInsecureHttp,
  };
}

function parseTimeout(value: string | undefined): number {
  if (value === undefined || value.trim() === "") return DEFAULT_TIMEOUT_MS;
  return Number(value);
}

function normalizeEndpoint(input: string, label: string, allowInsecureHttp: boolean, stripTrailingSlash = false): string {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error(`${label} must be an absolute URL.`);
  }
  if (url.protocol !== "https:" && !(allowInsecureHttp && url.protocol === "http:")) {
    throw new Error(`${label} must use HTTPS.`);
  }
  if (url.username || url.password || url.hash) throw new Error(`${label} must not contain userinfo or a fragment.`);
  if (stripTrailingSlash) {
    if (url.search) throw new Error(`${label} must not contain a query.`);
    url.pathname = url.pathname.replace(/\/$/, "");
  }
  return stripTrailingSlash ? url.toString().replace(/\/$/, "") : url.toString();
}

async function discoverUserInfoUrl(options: ResolvedOptions): Promise<string> {
  const response = await requestJson(options.discoveryUrl, {
    headers: { accept: "application/json" },
  }, options);
  if (!response.ok) throw new Error("OIDC discovery failed.");
  const metadata = object(await response.json());
  if (metadata.issuer !== undefined && normalizeComparableIssuer(metadata.issuer) !== options.issuer) {
    throw new Error("OIDC discovery issuer does not match configuration.");
  }
  if (typeof metadata.userinfo_endpoint !== "string" || !metadata.userinfo_endpoint.trim()) {
    throw new Error("OIDC discovery does not advertise a UserInfo endpoint.");
  }
  return normalizeEndpoint(metadata.userinfo_endpoint, "Discovered OIDC UserInfo endpoint", options.allowInsecureHttp);
}

async function fetchUserInfo(token: string, url: string, options: ResolvedOptions): Promise<UserInfo | null> {
  const response = await requestJson(url, {
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
    },
  }, options);
  if (response.status === 401 || response.status === 403) return null;
  if (!response.ok) throw new Error("OIDC UserInfo provider failed.");

  let payload: Record<string, unknown>;
  try {
    payload = object(await response.json());
  } catch {
    throw new Error("OIDC UserInfo response is invalid.");
  }
  if (typeof payload.sub !== "string" || !payload.sub.trim() || payload.sub.length > 512) return null;
  if (payload.iss !== undefined && normalizeComparableIssuer(payload.iss) !== options.issuer) return null;
  return { ...payload, sub: payload.sub };
}

async function requestJson(
  url: string,
  init: RequestInit,
  options: ResolvedOptions,
): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }> {
  const response = await options.fetch(url, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(options.timeoutMs),
  });
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
    throw new Error("OIDC provider response is too large.");
  }
  return {
    ok: response.ok,
    status: response.status,
    async json() {
      const text = await response.text();
      if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
        throw new Error("OIDC provider response is too large.");
      }
      return JSON.parse(text) as unknown;
    },
  };
}

function normalizeComparableIssuer(value: unknown): string | null {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    return new URL(value.trim()).toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("OIDC provider response must be an object.");
  }
  return value as Record<string, unknown>;
}

function projectAttributes(userInfo: UserInfo): Readonly<Record<string, string | readonly string[]>> {
  const entries: Array<readonly [string, string | readonly string[]]> = [];
  for (const key of ATTRIBUTE_KEYS) {
    const value = userInfo[key];
    if (typeof value === "string" && value.length <= 2_048) {
      entries.push([key, value]);
    } else if (
      Array.isArray(value)
      && value.length <= 32
      && value.every((entry) => typeof entry === "string" && entry.length <= 512)
    ) {
      entries.push([key, Object.freeze([...value] as string[])]);
    }
  }
  return Object.freeze(Object.fromEntries(entries));
}
