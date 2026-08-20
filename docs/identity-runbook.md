# Entra External ID, Apple, and Email OTP runbook

## Required owner-supplied values

- External ID tenant name and tenant ID
- Apple Developer Team ID, primary App ID, Services ID, Key ID, and the one-time-download `.p8`
- An administrator able to grant tenant-wide API consent

Never paste the `.p8`, generated Apple client secret, authorization code, ID token, or access token into this repository, an issue, build log, or chat.

## Registration contract

The identity bootstrap creates `soffortbackend-api` with Application ID URI `https://soffort.com/mcp` and delegated permission `soffortbackend.access`. It creates `soffortbackend-vscode` as a public client with these exact redirects:

- `http://127.0.0.1:33418`
- `https://vscode.dev/redirect`

Configure the Apple identity provider and user flow in the External ID portal. Register the
federation callback displayed by Entra in Apple Developer; it is an Entra `ciamlogin.com` URL, not
`https://soffort.com/mcp`. Enable Apple and Email One Time Passcode, allow self-service signup for
any verified inbox, associate the VS Code app, and grant admin consent to the API permission. Entra
sends and validates the email code; no mail credential belongs in this repository or AKS.

Use the exact `issuer` and `jwks_uri` returned by the tenant's OpenID Connect metadata. External ID may accept the friendly tenant subdomain for browser authorization while emitting the tenant-ID hostname in the token `iss` claim; the resource server deliberately validates the emitted value exactly.

## Compatibility gate

1. Before AKS exists, run `uv run scripts/test-identity-pkce.py --sign-in-method apple`, then rerun
   it with `--sign-in-method email`. Open each printed URL in Safari and use the named method. The
   probe keeps the authorization code and tokens in memory, validates PKCE, the MCP resource
   parameter, the JWT signature and claims, and prints only non-identifying facts.
2. Fetch the deployed API's RFC 9728 metadata without a token.
3. Connect from the current stable VS Code desktop using `.vscode/mcp.json`.
4. Confirm the browser offers Apple and verified-email OTP and completes PKCE using the loopback
   redirect for both methods.
5. Confirm `tools/list` shows only `hello_world` and a call returns the documented result.
6. Repeat through `vscode.dev`, including hidden-email, cancellation, returning login, and reconnect cases.

If Entra rejects the MCP resource parameter or VS Code cannot request the configured scope, stop the release. Record sanitized HTTP status, parameter names, and Entra correlation IDs; do not implement an OAuth proxy in the server.

### Development gate result (2026-08-19)

The repeatable PKCE probe passed the protocol checks against the configured External ID tenant:

- RS256 signature, exact issuer, API audience, tenant, and VS Code authorized-party claims
- `soffortbackend.access` delegated permission
- PKCE S256 and the MCP `resource=https://soffort.com/mcp` parameter
- authorization-code exchange and refresh-token issuance

The owner enabled open verified-email OTP registration. On 2026-08-20, Microsoft Graph reported the
active `soffortbackend_apple_email_v2` flow with both Apple and `EmailOtpSignup-OAUTH`, email required
for the local OTP path, self-signup enabled, and only `soffortbackend-vscode` associated. The earlier
flow remains unassociated as a rollback artifact and must not be treated as active configuration.

The fresh interactive compatibility test is currently **blocked**. Entra returns `AADSTS50058`
before rendering an identity provider. The result reproduced with:

- Safari and a separate clean browser context;
- no prompt, `prompt=login`, `prompt=select_account`, and `prompt=create`;
- minimal `openid` and the full MCP resource/scope request;
- Apple-only, Email-OTP-only, and combined provider configurations; and
- a freshly created, documented-schema user flow.

A cached Apple customer session had previously completed PKCE and produced a conforming API token,
so token issuance, audience, delegated scope, PKCE, and the MCP resource parameter have passed. A
fresh user cannot currently reach either provider, so Email OTP and first-time Apple registration
have not passed. Preserve the combined flow and stop before AKS provisioning. Resolve the hosted
Entra flow error through a successful portal "Run user flow" test or Microsoft support, then rerun
both probe modes and real VS Code desktop/`vscode.dev` before changing this gate.

The managed Entra Apple experience retains one product-policy exception:

- Apple's first-login sheet requested name and email. The Entra built-in Apple-provider form has no
  scope control, so the user-flow attribute configuration does not prevent that upstream request.

Do not provision AKS from this development branch until fresh Apple and Email OTP PKCE succeed and
the owner explicitly accepts the remaining managed Apple scope behavior or removes Apple. Do not
hide provider behavior with CSS and do not add a hand-written OAuth server.

## Credential renewal

Create a calendar/operations ticket at least 30 days before the Apple federation credential expires. Add the new credential in Entra, test first-time and returning login, then retire the old credential. The workload requires no restart because it has no Apple credential.
