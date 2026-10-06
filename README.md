# Orbit Auth OAuth 2.0 and OpenID Connect

`orbit-auth-oauth2` provides provider-neutral authorization-code flow orchestration over the stable
contracts in `orbit-auth`. It creates cryptographically random state, an OpenID nonce when an
issuer is configured, and an S256 PKCE challenge. It stores the verifier in a short-lived external
transaction store, atomically consumes callback state once, exchanges the authorization code, and
refuses OIDC identity unless a cryptographic ID-token verifier is configured.

```bash
pip install orbit-auth orbit-auth-oauth2
```

## Boundaries

This capability package owns the flow contract and security invariants. An application supplies an
`OAuthTransactionStore` backed by shared storage with atomic read-and-delete semantics. Provider
adapters implement `OAuth2Provider` and own issuer/authorization endpoints, vendor SDKs,
credentials, HTTP transport, JWKS retrieval/key rotation, cryptographic ID-token validation, and
provider-specific error mapping. The flow binds redirects to the adapter's configured HTTPS
authorization endpoint and checks the same adapter configuration at callback time. `orbit-auth-oauth2`
does not provide a process-local store or provider SDK, and it performs no network requests.

The store must enforce TTLs, protect PKCE verifiers at rest, bound stored values, and be shared by
all application workers. Its keys are SHA-256 digests of the high-entropy OAuth `state`; it must not
log keys or transaction contents. `begin()` and `complete()` require the same 32-character-or-longer
`session_binding`: an opaque high-entropy value tied to the initiating browser session. Store
implementations must atomically compare its digest and consume the transaction only on a match, so
a callback from another browser cannot burn or complete the flow. Use a secure session cookie
(`Secure`, `HttpOnly`, and an appropriate `SameSite` policy) or an equivalent server-owned binding;
never use a user identifier or other low-entropy value. The default transaction lifetime is 10
minutes and may be set from 30 seconds to 30 minutes. Implementations must make `take()` atomic so
concurrent callbacks cannot exchange a code twice.

For OpenID Connect, pass the configured issuer to `begin()` and configure an `IDTokenVerifier`.
The verifier must validate the signature using keys trusted for that issuer and check issuer,
audience, authorized party, token time claims, and nonce. The flow independently binds returned
issuer/audience/expiry/nonce claims to the single-use transaction. A JWT parser without signature
and issuer-key validation is not an acceptable verifier. OAuth token exchange errors and callback
state failures are exposed as generic typed errors; provider descriptions and raw credentials are
not retained in exception text. Authorization codes are not retried after transaction consumption;
start a new login after cancellation or a network failure.

The API is pre-alpha and unpublished. This package currently has no Redis/database store, HTTP
client, concrete OIDC verifier, vendor adapter, or live identity-provider validation. Production
use requires independently reviewed adapters and deployment-specific state-store protection,
redirect URI registration, cookie/session binding, CSRF policy, key rotation, and incident/revocation
handling. Never put client secrets in source control or browser code; use a confidential backend and
a secret manager where applicable.

## Documentation

The package-specific guides cover [architecture](docs/architecture/overview.md), [operations and security](docs/operations/README.md), and [development](docs/development/README.md), with [security guidance](docs/security/overview.md). The [documentation index](docs/README.md) links to the full package overview and project policies.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
ruff format --check .
mypy
```

Licensed under Apache-2.0.

