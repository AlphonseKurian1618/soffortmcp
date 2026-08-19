# ADR 0001: Entra External ID federates Apple authentication

Status: accepted

## Decision

Microsoft Entra External ID is the OAuth authorization server. Apple is its only upstream identity provider. `soffortbackend` is strictly an OAuth resource server and accepts only Entra-issued, audience-bound access tokens.

The API and VS Code client use separate Entra registrations. The API exposes `soffortbackend.access`; the VS Code registration is a public client using authorization code plus PKCE and has no secret.

## Rationale

Apple tokens target an Apple Services ID and do not implement the discovery, resource indication, client registration, and API audience contract required by remote MCP clients. Passing an Apple token to `/mcp` would conflate user authentication with API authorization.

## Consequences

- The Apple `.p8` and federation client secret never enter the application or cluster.
- The server keys users by no local identifier because it stores no user data.
- Entra/VS Code interoperability must pass before deployment.
- Operators renew the Apple federation credential before its six-month deadline.

