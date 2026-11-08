# Authelia OIDC clients for chat apps

Authelia has no dynamic client registration, so each chat app gets one preregistered client. Add it under `identity_providers.oidc.clients`, validate with `authelia validate-config`, and apply in the owner's maintenance window. Check field names against the documentation for your Authelia version before applying.

## Public client (PKCE, no secret)

Use for apps that support a public client with PKCE, such as ChatGPT, Claude Code, Codex and Grok:

```yaml
- client_id: <app>-<mcp-name>
  client_name: <App> <MCP name>
  public: true
  authorization_policy: two_factor
  require_pkce: true
  pkce_challenge_method: S256
  redirect_uris:
    - <exact callback copied from the app>
  audience:
    - https://<mcp-host>/mcp
  scopes: [<narrow MCP scopes>]
  grant_types: [authorization_code, refresh_token]
  response_types: [code]
  token_endpoint_auth_method: none
  access_token_signed_response_alg: RS256
```

The MCP server in this pattern needs signed JWT access tokens (`at+jwt`) whose audience is exactly the resource URL. Keep scopes to the tools the app needs. Add `offline_access` to the client's scopes only if the app must refresh tokens without the user.

## Confidential client (secret)

Some apps, such as Superhuman Packs without dynamic registration, expect a client secret. Set `public: false`, `token_endpoint_auth_method: client_secret_basic` (or what the app documents), and a `client_secret` stored as a hashed digest. Generate and hand over the plaintext secret only through a private channel; the app's settings form is the only other place it may appear.

## Change safety

- Add clients; do not edit existing ones in the same change unless that is the task.
- Preserve signing keys, HMAC secret and storage so existing tokens and sessions survive.
- A restart can end in-memory sessions. Schedule it with the owner of the Authelia deployment.
- After applying, verify each existing client still works before adding the next app.
