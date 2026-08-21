# Entra External ID, Apple, and Email OTP runbook

## Required owner-supplied values

- External ID tenant name and tenant ID
- Apple Developer Team ID, primary App ID, Services ID, Key ID, and the one-time-download `.p8`
- An administrator able to grant tenant-wide API consent

Never paste the `.p8`, generated Apple client secret, authorization code, ID token, or access token into this repository, an issue, build log, or chat.

## Registration contract

The identity bootstrap creates `soffortbackend-api` with Application ID URI `https://soffort.com/mcp` and delegated permissions `soffortbackend.access` and `soffortbackend.mobile`. It creates `soffortbackend-vscode` as a public client with these exact redirects:

- `http://127.0.0.1:33418`
- `https://vscode.dev/redirect`

It also creates the secretless `soffortbackend-ios` public client with redirect `msauth.com.soffort.aivault://auth`. VS Code receives only `soffortbackend.access`; iOS receives only `soffortbackend.mobile`. The current non-secret iOS client ID is `dcae2fbc-315f-41b0-9c47-17482098cbab`.

Configure the Apple identity provider and user flow in the External ID portal. Register the
federation callback displayed by Entra in Apple Developer; it is an Entra `ciamlogin.com` URL, not
`https://soffort.com/mcp`. Enable Apple and Email One Time Passcode, allow self-service signup for
any verified inbox, associate both public clients, and grant admin consent to their separate API permissions. Entra
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
5. On a physical iPhone, confirm MSAL uses the same hosted flow and obtains only `soffortbackend.mobile`. A different provider/account must remain a separate identity.
6. Confirm `tools/list` shows only `hello_world`; complete the phone decision and confirm the call returns the documented result.
7. Repeat through `vscode.dev`, including hidden-email, cancellation, returning login, and reconnect cases.

If Entra rejects the MCP resource parameter or VS Code cannot request the configured scope, stop the release. Record sanitized HTTP status, parameter names, and Entra correlation IDs; do not implement an OAuth proxy in the server.

### Development gate result (2026-08-20)

The repeatable PKCE probe passed the protocol checks against the configured External ID tenant:

- RS256 signature, exact issuer, API audience, tenant, and VS Code authorized-party claims
- `soffortbackend.access` delegated permission
- PKCE S256 and the MCP `resource=https://soffort.com/mcp` parameter
- authorization-code exchange and refresh-token issuance

The owner enabled open verified-email OTP registration. On 2026-08-20, Microsoft Graph reported the
active `soffortbackend_apple_email_v2` flow with both Apple and `EmailOtpSignup-OAUTH`, email required
for the local OTP path, and self-signup enabled. Phase 2 associated both `soffortbackend-vscode` and
`soffortbackend-ios` with that active flow through Microsoft Graph. The earlier
flow remains unassociated as a rollback artifact and must not be treated as active configuration.

Fresh Apple authentication now passes when the probe includes Microsoft's documented issuer
acceleration parameter `domain_hint=apple`. The 2026-08-20 run reached the native Apple sheet and
then passed the complete token validation list above. Apple authentication can therefore be used
for the VS Code MCP acceptance path.

The generic hosted provider page and email OTP path remain **blocked**. Entra returns `AADSTS50058`
before rendering a provider. The result reproduced with:

- Safari and a separate clean browser context;
- no prompt, `prompt=login`, `prompt=select_account`, and `prompt=create`;
- minimal `openid` and the full MCP resource/scope request;
- Apple-only, Email-OTP-only, and combined provider configurations; and
- a freshly created, documented-schema user flow.

A fresh user can reach Apple directly, but cannot currently reach email OTP through the managed
picker. Preserve the combined flow and do not claim email E2E support until the portal "Run user
flow" test or Microsoft support resolves the hosted page. The Apple path is sufficient to continue
the cost-capped development deployment and real VS Code gate; email remains a separately recorded
acceptance failure.

The managed Entra Apple experience retains one product-policy exception:

- Apple's first-login sheet requested name and email. The Entra built-in Apple-provider form has no
  scope control, so the user-flow attribute configuration does not prevent that upstream request.

Do not promote beyond the Apple-authenticated development path until Email OTP PKCE succeeds. Do
not hide provider behavior with CSS and do not add a hand-written OAuth server.

## Credential renewal

Create a calendar/operations ticket at least 30 days before the Apple federation credential expires. Add the new credential in Entra, test first-time and returning login, then retire the old credential. The workload requires no restart because it has no Apple credential.
