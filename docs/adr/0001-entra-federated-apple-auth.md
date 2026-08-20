# ADR 0001: Entra External ID brokers Apple and email OTP authentication

Status: accepted

## Decision

Microsoft Entra External ID is the OAuth authorization server. Users authenticate through Apple or
an Entra-managed email one-time passcode. `soffortbackend` is strictly an OAuth resource server and
accepts only Entra-issued, audience-bound access tokens.

The API and VS Code client use separate Entra registrations. The API exposes `soffortbackend.access`; the VS Code registration is a public client using authorization code plus PKCE and has no secret.

## Rationale

Apple tokens target an Apple Services ID, and an email OTP proves control of an inbox; neither is an
MCP API credential. Entra converts either authentication result into the same discovery, resource
indication, PKCE, delegated-scope, and API-audience contract required by remote MCP clients.

## Consequences

- The Apple `.p8` and federation client secret never enter the application or cluster.
- Entra sends and validates email codes, so the application needs no password database or email
  delivery service.
- The server keys users by no local identifier because it stores no user data.
- Apple and email identities are not merged by email address. If persistent user data is added,
  identity must use the trusted issuer and subject rather than a mutable or relay email address.
- Any person controlling an email inbox can self-register. A future sensitive tool requires a
  separate authorization policy; successful authentication alone is not an allowlist.
- Email OTP is the primary factor and therefore cannot also be the user's MFA factor.
- Entra/VS Code interoperability must pass before deployment.
- Operators renew the Apple federation credential before its six-month deadline.
