# OAuth 2.0 and OpenID Connect security

This package coordinates authorization-code flows and enforces callback invariants. It does not
own browser cookies, provider credentials, network transport, durable storage, ID-token keys, or
application authorization policy. Those boundaries must be configured by the application and
provider adapter.

## Request protections

- **State:** each login uses 32 bytes from the cryptographic random generator, encoded as exactly
  43 unpadded base64url characters. The callback rejects other shapes before hashing or accessing
  the transaction store. State is single-use and expires after a bounded lifetime. The callback
  also rejects a stored transaction whose expiry is not a finite Unix timestamp before exchanging
  a code, so malformed persisted state cannot bypass the deadline comparison.
- **PKCE:** each login uses a fresh high-entropy verifier and an S256 challenge. Store the verifier
  only for that transaction, protect it at rest, and erase it when the transaction is consumed or
  expires. The `plain` method is rejected.
- **Browser binding:** supply a fresh, unpredictable session binding associated with the initiating
  browser session. Do not use a user ID, IP address, or other guessable value. The store must
  atomically compare the binding digest and consume the transaction only on a match; a mismatch
  must not burn another browser's valid transaction.
- **Redirects:** register the exact callback URI at the identity provider and use HTTPS outside
  localhost development. Do not derive redirect URIs from untrusted `Host` or forwarding headers.
  The package checks that the provider adapter preserves the trusted authorization endpoint and
  mandatory OAuth parameters.

Use a cookie or equivalent server-owned session binding with `Secure`, `HttpOnly`, and an
appropriate `SameSite` policy. Applications remain responsible for cookie scope, CSRF policy,
session rotation, and reverse-proxy trust configuration.

## OpenID Connect identity

OAuth access tokens do not prove a user identity. For OIDC, pass the configured issuer to
`begin()` and supply an `IDTokenVerifier` that validates the ID-token signature using keys trusted
for that issuer. The adapter must validate issuer, audience, authorized party, expiry, issued-at,
`nbf` when present, and nonce. The flow independently checks the returned issuer, audience,
expiry, and nonce against the stored transaction. Do not implement the verifier by merely decoding
JWT claims or by accepting keys from untrusted token headers.

Use maintained issuer metadata/JWKS integration for key discovery and rotation, pin the expected
issuer, allow only the algorithms configured for that issuer, and plan a rotation and outage
procedure. Those responsibilities belong to an adapter and are not supplied by this capability.

## Secrets and diagnostics

Keep client secrets and PKCE verifiers in backend-controlled secret storage. Never ship a
confidential client secret to browser code. Do not log authorization URLs, callback query strings,
authorization codes, state, nonce, access/refresh tokens, ID tokens, session bindings, raw provider
exceptions, or transaction contents. Package result and transaction representations redact secret
values; this does not prevent application logs from exposing explicitly accessed fields.

The package sanitizes provider exchange failures and ignores provider-supplied error descriptions.
Callback state and authorization codes are consumed before exchange; after cancellation or an
ambiguous network failure, start a new authorization flow rather than retrying the same code.

## Limits and deployment responsibilities

Transactions have a default ten-minute lifetime, configurable from 30 seconds to 30 minutes. The
store contract requires bounded storage, TTL enforcement, protected verifier values, shared state
across workers, and atomic consume semantics. This repository supplies no production store,
provider SDK, ID-token verifier, key discovery, credential revocation, or live identity-provider
acceptance test. Review those integrations and the cookie, redirect, secret, and incident response
configuration before deployment.

For vulnerability reporting, follow the repository [security policy](../../SECURITY.md). Do not
publish exploitable details in public issues.
