# Entra External ID and Apple runbook

## Required owner-supplied values

- External ID tenant name and tenant ID
- Apple Developer Team ID, primary App ID, Services ID, Key ID, and the one-time-download `.p8`
- An administrator able to grant tenant-wide API consent

Never paste the `.p8`, generated Apple client secret, authorization code, ID token, or access token into this repository, an issue, build log, or chat.

## Registration contract

The identity bootstrap creates `soffortbackend-api` with Application ID URI `https://soffort.com/mcp` and delegated permission `soffortbackend.access`. It creates `soffortbackend-vscode` as a public client with these exact redirects:

- `http://127.0.0.1:33418`
- `https://vscode.dev/redirect`

Configure the Apple identity provider and user flow in the External ID portal. Register the federation callback displayed by Entra in Apple Developer; it is an Entra `ciamlogin.com` URL, not `https://soffort.com/mcp`. Offer Apple only, enable self-service signup, request no name/email scope, associate the VS Code app, and grant admin consent to the API permission.

Use the exact `issuer` and `jwks_uri` returned by the tenant's OpenID Connect metadata. External ID may accept the friendly tenant subdomain for browser authorization while emitting the tenant-ID hostname in the token `iss` claim; the resource server deliberately validates the emitted value exactly.

## Compatibility gate

1. Before AKS exists, run `uv run scripts/test-identity-pkce.py`. Open the printed URL in
   Safari and complete Apple sign-in. The probe keeps the authorization code and tokens in
   memory, validates PKCE, the MCP resource parameter, the JWT signature and claims, and prints
   only non-identifying booleans.
2. Fetch the deployed API's RFC 9728 metadata without a token.
3. Connect from the current stable VS Code desktop using `.vscode/mcp.json`.
4. Confirm the browser offers only Apple and completes PKCE using the loopback redirect.
5. Confirm `tools/list` shows only `hello_world` and a call returns the documented result.
6. Repeat through `vscode.dev`, including hidden-email, cancellation, returning login, and reconnect cases.

If Entra rejects the MCP resource parameter or VS Code cannot request the configured scope, stop the release. Record sanitized HTTP status, parameter names, and Entra correlation IDs; do not implement an OAuth proxy in the server.

### Development gate result (2026-08-19)

The repeatable PKCE probe passed the protocol checks against the configured External ID tenant:

- RS256 signature, exact issuer, API audience, tenant, and VS Code authorized-party claims
- `soffortbackend.access` delegated permission
- PKCE S256 and the MCP `resource=https://soffort.com/mcp` parameter
- authorization-code exchange and refresh-token issuance

The managed Entra Apple experience did **not** pass two product-policy checks:

- The initial Entra page still displayed an email-address sign-in path even after Microsoft Graph
  reported Apple as the flow's only identity provider.
- Apple's first-login sheet requested name and email. The Entra built-in Apple-provider form has no
  scope control, so making the flow email attribute optional does not prevent that upstream request.

Do not provision AKS from this development branch until the owner explicitly accepts both managed
provider behaviors or selects a different standards-compliant authorization service. Do not hide the
email option with CSS and do not add a hand-written OAuth server.

## Credential renewal

Create a calendar/operations ticket at least 30 days before the Apple federation credential expires. Add the new credential in Entra, test first-time and returning login, then retire the old credential. The workload requires no restart because it has no Apple credential.
