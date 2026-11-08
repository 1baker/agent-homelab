# Connect a chat app

Always confirm the callback in the app or its current official documentation before registering it. Values below were checked in November 2026 and can change.

| App | Where to add | Callback | Client type |
|---|---|---|---|
| ChatGPT | Settings → Apps/Connectors → Create (developer mode) | Shown by ChatGPT when creating the connector | Public PKCE, client ID entered in the form |
| Claude (web, desktop, mobile) | Settings → Connectors → Add custom connector → Advanced settings for client ID | `https://claude.ai/api/mcp/auth_callback` and `https://claude.com/api/mcp/auth_callback` (register both) | Public PKCE, or client ID + secret |
| Claude Code | `claude mcp add --transport http <name> https://<mcp-host>/mcp` then `/mcp` to sign in | Local loopback callback; check `claude mcp add --help` for the fixed callback-port and client-ID options | Public PKCE |
| Codex | `codex mcp add` / `codex mcp login`; check current `--help` | Local loopback callback shown by Codex | Public PKCE |
| Grok | grok.com/connectors → New Connector → Custom | Shown in the OAuth credentials dialog | Public PKCE, client ID entered in the dialog |
| Superhuman Go | Build a Pack with the Packs SDK, release it, then Go → Connectors → Sign in | `https://docs.superhuman.com/packsAuth/oauth2/<pack-id>` (exact value in Pack Settings → Add OAuth credentials) | Usually confidential (client ID + secret) |

## Superhuman Go Pack

Requires a Superhuman Pro plan or higher and Doc Maker access. A Pack connects to exactly one MCP server:

```ts
import * as sdk from "@codahq/packs-sdk";
export const pack = sdk.newPack();

pack.addNetworkDomain("<root-domain>");
pack.setUserAuthentication({
  type: sdk.AuthenticationType.OAuth2,
  authorizationUrl: "https://<auth-host>/api/oidc/authorization",
  tokenUrl: "https://<auth-host>/api/oidc/token",
  scopes: ["<narrow MCP scopes>"],
  useProofKeyForCodeExchange: true,
});
pack.addMCPServer({ name: "<letters_numbers_underscores>", endpointUrl: "https://<mcp-host>/mcp" });
```

Upload and release with `npx packs upload pack.ts` and `npx packs release pack.ts --notes "<notes>"`, then add the client credentials in Pack Settings. Do not use `useDynamicClientRegistration` against Authelia. Confirm the token request carries the MCP resource as audience; if the Pack cannot send it, configure the Authelia client's default audience.

## Proof per app

For each app, record separately: client registered, connector added, sign-in completed, `tools/list` returned the expected tools, one read-only tool call succeeded. A listed connector without a tool call is not working.
