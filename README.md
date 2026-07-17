# @jinshuju/eve-oidc

Eve-compatible route authentication for Jinshuju OIDC. It accepts opaque Bearer access tokens, verifies them through the provider UserInfo endpoint, and maps the verified subject to Eve 0.24.6 `SessionAuthContext`.

## Install

```bash
pnpm add @jinshuju/eve-oidc eve
```

## Use with Eve

```ts
import { eveChannel } from "eve/channels/eve";
import { localDev } from "eve/channels/auth";
import { jinshujuOidc } from "@jinshuju/eve-oidc";

export default eveChannel({
  auth: [jinshujuOidc(), localDev()],
});
```

The factory resolves runtime configuration when `jinshujuOidc()` is called. Missing or unsafe configuration fails closed.

| Environment variable | Required | Purpose |
| --- | --- | --- |
| `JINSHUJU_OIDC_ISSUER` | yes | Exact HTTPS issuer identifier. |
| `JINSHUJU_OIDC_USERINFO_URL` | no | HTTPS UserInfo endpoint. When omitted, OIDC discovery is used. |
| `JINSHUJU_OIDC_DISCOVERY_URL` | no | Discovery endpoint override. Defaults to `<issuer>/.well-known/openid-configuration`. |
| `JINSHUJU_OIDC_TIMEOUT_MS` | no | Provider request timeout from 100–60000 ms. Defaults to 5000. |

Explicit options override environment values, which makes tests and non-Eveland deployments straightforward:

```ts
jinshujuOidc({
  issuer: "https://identity.example.com",
  userInfoUrl: "https://identity.example.com/oauth2/userinfo",
});
```

The verifier never logs or returns access tokens, provider response bodies, or recoverable secrets. UserInfo `sub` becomes the Eve subject; only a small set of string profile attributes is projected.

## Eveland

In Eveland, configure the Agent runtime variables through a Project Secret or `agent-runtime` Platform Secret Profile. Configure Playground separately with the generic OIDC Authorization Code Connection; the Agent verifier does not need the OAuth client secret.

## Development

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm build
```
