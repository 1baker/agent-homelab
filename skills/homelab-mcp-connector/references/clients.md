# Chat app callbacks and Authelia client types

Use this table to write each app's Authelia client (see `authelia-clients.md`). Adding the connector in the app, signing in and proving a tool call belong to `mcp-onboarding`.

Always confirm the callback in the app or its current official documentation before registering it. Values below were checked in November 2026 and can change.

| App | Callback to register | Authelia client type |
|---|---|---|
| ChatGPT | Shown when creating the connector (Settings → Apps/Connectors → Create, developer mode) | Public PKCE; the app takes a client ID |
| Claude (web, desktop, mobile) | `https://claude.ai/api/mcp/auth_callback` and `https://claude.com/api/mcp/auth_callback` (register both); the client ID goes under Settings → Connectors → Add custom connector → Advanced settings | Public PKCE, or client ID + secret |
| Claude Code | Local loopback callback; check `claude mcp add --help` for the fixed callback-port and client-ID options | Public PKCE |
| Codex | Local loopback callback shown by `codex mcp login`; check current `codex mcp --help` | Public PKCE |
| Grok | Shown in the OAuth credentials dialog (grok.com/connectors → New Connector → Custom) | Manual client ID, optional secret, token auth `none` with PKCE |
| Superhuman Go | Shown in the custom MCP connector's OAuth form (Go → Connectors) | Confidential: client ID **and** secret required |

Superhuman Go's native connector form (observed November 2026) needs a confidential Authelia client; hand the secret over only through a private channel into that form. A Pack is not required for this flow.

## Superhuman Go Pack (alternative)

Building, uploading and configuring a Pack is client-side setup that belongs to `mcp-onboarding`, which does not cover Packs yet. Treat a Pack as unsupported here: register its Authelia client, then hand it off as deferred. Use one only if the native form cannot be used.

Authelia requirements for a Pack client:

- Callback: `https://docs.superhuman.com/packsAuth/oauth2/<pack-id>` (exact value in Pack Settings → Add OAuth credentials).
- Client type: confidential (client ID and secret), with PKCE (`S256`).
- Endpoints the Pack uses: `https://<auth-host>/api/oidc/authorization` and `https://<auth-host>/api/oidc/token`, with narrow MCP scopes.
- No dynamic client registration: the Pack must not use `useDynamicClientRegistration` against Authelia; preregister its client.
- Audience: the token request must carry the MCP resource (`https://<mcp-host>/mcp`) as audience; if the Pack cannot send it, configure the Authelia client's default audience.
- A Pack connects to exactly one MCP server.

## After registration

Record that the Authelia client is registered and applied, then hand the app to `mcp-onboarding` for the connector, sign-in and tool-call proof. A registered client or a listed connector without a tool call is not a working connection.
