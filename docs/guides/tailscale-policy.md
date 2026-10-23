# Scoped Tailscale policy access

This optional CLI manages the existing tailnet policy through Tailscale's API.
It does not install Tailscale, enroll devices, change Serve mappings, configure
Traefik or replace Authelia. Start with a reader. Real provider acceptance must
be verified after enrollment; offline tests cannot establish it.

## Human credential bootstrap

In the existing Tailscale admin session, an authorized human opens **Trust
credentials**, chooses **Credential → OAuth**, and creates the reader with:

- `policy_file:read`
- `devices:posture_attributes:read`
- `devices:core:read`

These are the documented companion scopes, not all-access. Do not create an
auth key or a full-permission personal API key. Create a writer only when an
exact reviewed candidate needs one. A writer uses `policy_file`,
`devices:posture_attributes`, and `devices:core:read`; those permissions are
broader than one grant or port. Application checks enforce the narrower effect.

On the intended Linux operator account, use the reviewed installed CLI in a
human-controlled terminal. Replace the example absolute paths below with a
private location owned by that operator, outside every Git worktree. No secret
belongs in chat, a command argument, shell history, a report or a preview.

```sh
agent-homelab tailscale-policy enroll --credential-file /private/homelab-tailscale/reader.json
```

In plain English: enter the client ID and one-time secret at the hidden terminal
prompts. This creates a new private credential file and refuses an existing
file. The provider values stay on that machine; do not paste them into chat.

The directory must be private (`0700`), and files must be regular,
operator-owned `0600` files. Symlinks, unsafe ownership or permissions, and Git
worktrees are rejected. Keep credential state separate from policy snapshots
and never publish either. Access tokens are obtained from the fixed HTTPS token
endpoint and remain in memory. Revocation happens through the provider admin
console; the CLI does not mint or revoke credentials.

Check every ancestor before choosing the private state root. An entire home
directory can be a Git worktree for dotfiles; an ignored subdirectory inside it
still fails the outside-Git requirement. Use a dedicated durable directory
outside that worktree, created by the operator's administrator when necessary.
Temporary or runtime directories are not a durable credential default. A
home-only backup cannot recover outside-home state; retain a private backup or
plan to revoke and enroll a new reader credential after state loss.

Enrollment checks Git ancestry, symlinks and an existing destination before
checking for a terminal. These checks create nothing. Only a valid destination
with a human terminal proceeds to directory checks and hidden prompts. Staging
must inspect every intended private path and its ownership/permissions; a
terminal-required error alone is not complete enrollment acceptance.

## Inventory

Add this optional section to a validated private inventory:

```yaml
tailscale:
  authority: console
  credential_ref:
    file: /private/homelab-tailscale/reader.json
```

In plain English: this stores the location of the reader credential, not its
contents. Set the authority to `gitops` when a repository controls policy; that
setting makes direct API apply and rollback refuse to write.

A reference may instead be `{env: HOMELAB_TAILSCALE_READER}`. Only that explicitly
named variable is read, containing the same credential JSON. Provision it via a
private service environment, never by an inline shell assignment. The CLI does
not hunt other environment variables or fall back to a broadly capable key.
No writer reference is present in the initial reader inventory. Normal
`agent-homelab validate` checks references without loading any secret.

## Read and preview

```sh
agent-homelab tailscale-policy read --inventory /private/homelab.yaml --snapshot-dir /private/policy-snapshot
agent-homelab tailscale-policy plan --inventory /private/homelab.yaml --snapshot /private/policy-snapshot --candidate /private/candidate.hujson --plan-dir /private/policy-plan
```

In plain English: read saves the exact current policy and version in a new
private directory. Plan compares a private candidate with that snapshot and asks
Tailscale to validate it. These commands save private files and make no policy
change. Review the exact diff privately before considering apply.

Raw HuJSON bytes, comments and unknown fields are retained. The snapshot manifest
binds the bytes to a SHA-256 digest, authority and exact ETag. A candidate must
already exist as a private, operator-owned file outside Git. The CLI accepts
reviewed bytes; it does not invent policy edits or derive grants from a device's
compiled filter.

Validation succeeds only when the provider returns HTTP 200 with an empty body.
A nonempty body means failure. A reader denied validation records
`VALIDATION_UNAVAILABLE`; it does not silently promote a local diff to successful
provider validation. Check this with the actual scoped reader before claiming
live read/plan acceptance. Public status contains outcomes and hashes; full
policy bytes and diffs stay private. Provider errors are classified without
retaining or printing their response bodies.

## Conditional writes, deferred until needed

A separate writer reference must be configured explicitly. Leave it absent for
the initial reader deployment. Never reuse the reader reference as the writer.
The following is the interface for a later reviewed policy change:

```sh
agent-homelab tailscale-policy apply --inventory /private/homelab.yaml --snapshot /private/policy-snapshot --candidate /private/candidate.hujson --expect-etag REVIEWED_ETAG --candidate-sha256 REVIEWED_SHA256 --receipt-dir /private/policy-attempt --apply
```

In plain English: this can replace the remote policy. It requires the reviewed
candidate hash, current policy version, a configured writer and explicit apply.
A different current policy or failed validation stops the operation before it
changes access. Keep the private receipt for readback and possible rollback.

Apply refuses GitOps authority and missing writer configuration before obtaining
credentials or contacting the provider. It checks candidate hash, snapshot
integrity, current ETag and current raw bytes, then validates using the writer
and sends one `If-Match` conditional POST. A version conflict (`412`) stops
without rebasing or retry. If the write outcome is uncertain, the CLI reads the
current state once and preserves an attempt receipt; it does not send another
POST automatically. Inspect that receipt before any new manual attempt.
Success also requires the write response's own ETag and exact matching readback;
a later read alone cannot identify which operator created a policy version.

Rollback is also explicit and conditional. It may restore the verified original
snapshot only while the ETag produced by this operation is still current. A
subsequent edit by another operator blocks rollback. There is no automatic
rollback that could overwrite a later version.

```sh
agent-homelab tailscale-policy rollback --inventory /private/homelab.yaml --receipt /private/policy-attempt/receipt.json --receipt-dir /private/policy-rollback --apply
```

In plain English: this can restore the previous remote policy using a confirmed
write receipt. It refuses if another policy version has appeared, so it cannot
silently undo a later operator's edit. It saves a separate private rollback receipt.

## Evidence and limits

Keep four results separate: source implementation, offline fixtures, installed
CLI, and actual API behavior. A valid inventory, stored reference or successful
help command proves neither provider access nor policy effect. An initial reader
installation does not authorize provisioning a writer or applying a candidate.

Policy authority is an operator declaration. Verify it in the existing admin
console or the canonical GitOps repository before writes. The API endpoint and
OAuth token endpoint are fixed HTTPS Tailscale addresses; redirects are refused.
Error output is sanitized, not a dump of provider responses or credential files.

Sources: [OAuth clients](https://tailscale.com/docs/features/oauth-clients),
[scope dependencies](https://tailscale.com/docs/reference/trust-credentials), and
[official raw-policy client](https://github.com/tailscale/tailscale-client-go-v2/blob/main/policyfile.go).
