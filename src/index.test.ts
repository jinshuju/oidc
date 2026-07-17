import { routeAuth } from "eve/channels/auth";
import { afterEach, describe, expect, test, vi } from "vitest";
import { jinshujuOidc } from "./index.js";

const issuer = "https://identity.jinshuju.example";
const userInfoUrl = `${issuer}/oauth2/userinfo`;

afterEach(() => {
  vi.restoreAllMocks();
});

describe("jinshujuOidc", () => {
  test("maps an opaque access token and UserInfo subject to Eve SessionAuthContext", async () => {
    const fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer opaque-access-token");
      expect(init?.redirect).toBe("error");
      return Response.json({
        sub: "user_123",
        email: "member@example.com",
        name: "Member",
        groups: ["builders", "admins"],
        email_verified: true,
        secret_internal_claim: { value: "must-not-project" },
      });
    });
    const auth = jinshujuOidc({ issuer, userInfoUrl, fetch });

    await expect(auth(request("opaque-access-token"))).resolves.toEqual({
      attributes: {
        email: "member@example.com",
        groups: ["builders", "admins"],
        name: "Member",
      },
      authenticator: "jinshuju-oidc",
      issuer,
      principalId: `${issuer}:user_123`,
      principalType: "user",
      subject: "user_123",
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test("skips requests without a valid Bearer credential without contacting the provider", async () => {
    const fetch = vi.fn();
    const auth = jinshujuOidc({ issuer, userInfoUrl, fetch });

    await expect(auth(new Request("https://agent.example/eve/v1/session"))).resolves.toBeNull();
    await expect(auth(new Request("https://agent.example/eve/v1/session", {
      headers: { authorization: "Basic dXNlcjpwYXNz" },
    }))).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  test.each([
    [401, "invalid token"],
    [403, "expired token"],
  ])("rejects invalid or expired tokens returned as HTTP %i", async (status, body) => {
    const auth = jinshujuOidc({
      issuer,
      userInfoUrl,
      fetch: async () => new Response(body, { status }),
    });

    await expect(auth(request("rejected-secret-token"))).resolves.toBeNull();
  });

  test.each([
    { payload: {}, label: "missing subject" },
    { payload: { sub: "" }, label: "empty subject" },
    { payload: { sub: "user_123", iss: "https://attacker.example" }, label: "issuer mismatch" },
  ])("rejects malformed UserInfo: $label", async ({ payload }) => {
    const auth = jinshujuOidc({
      issuer,
      userInfoUrl,
      fetch: async () => Response.json(payload),
    });

    await expect(auth(request("opaque-token"))).resolves.toBeNull();
  });

  test("turns provider failures into a sanitized Eve 401 without leaking the token", async () => {
    const token = "provider-failure-secret-token";
    const auth = jinshujuOidc({
      issuer,
      userInfoUrl,
      fetch: async () => new Response(`upstream leaked ${token}`, { status: 503 }),
    });

    const result = await routeAuth(request(token), auth);

    expect(result).toBeInstanceOf(Response);
    const response = result as Response;
    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.text();
    expect(body).toContain("jinshuju_oidc_provider_unavailable");
    expect(body).not.toContain(token);
    expect(body).not.toContain("upstream leaked");
  });

  test("discovers and caches UserInfo metadata per authenticator instance", async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return Response.json({ issuer, userinfo_endpoint: userInfoUrl });
      }
      return Response.json({ sub: url.endsWith("userinfo") ? "user_123" : "wrong" });
    });
    const auth = jinshujuOidc({ issuer, fetch });

    await expect(auth(request("token-one"))).resolves.toMatchObject({ subject: "user_123" });
    await expect(auth(request("token-two"))).resolves.toMatchObject({ subject: "user_123" });
    expect(fetch.mock.calls.map(([input]) => String(input))).toEqual([
      `${issuer}/.well-known/openid-configuration`,
      userInfoUrl,
      userInfoUrl,
    ]);
  });

  test("reads runtime configuration when the factory is called and lets explicit options override env", async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toBe("https://override.example/userinfo");
      return Response.json({ sub: "user_123" });
    });
    const auth = jinshujuOidc({
      issuer,
      userInfoUrl: "https://override.example/userinfo",
      fetch,
      env: {
        JINSHUJU_OIDC_ISSUER: "https://ignored.example",
        JINSHUJU_OIDC_USERINFO_URL: "https://ignored.example/userinfo",
      },
    });

    await expect(auth(request("token"))).resolves.toMatchObject({ issuer, subject: "user_123" });
  });

  test("fails closed when required runtime configuration is absent or unsafe", () => {
    expect(() => jinshujuOidc({ env: {} })).toThrow(/JINSHUJU_OIDC_ISSUER/);
    expect(() => jinshujuOidc({ issuer: "http://identity.example", userInfoUrl })).toThrow(/HTTPS/);
    expect(() => jinshujuOidc({ issuer, userInfoUrl: "http://identity.example/userinfo" })).toThrow(/HTTPS/);
  });
});

function request(token: string): Request {
  return new Request("https://agent.example/eve/v1/session", {
    headers: { authorization: `Bearer ${token}` },
  });
}
