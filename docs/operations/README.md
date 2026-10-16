# OAuth 2.0 and OpenID Connect operations

`orbit-auth-oauth2` coordinates one authorization-code login at a time. Applications provide the
transaction store, browser session binding, callback route, and provider adapter. Install the
capability alongside `orbit-auth`:

```bash
python -m pip install orbit-auth orbit-auth-oauth2
```

For the public contracts and provider boundary, see the [architecture guide](../architecture/overview.md).
For attack surface and deployment safeguards, see the [security guide](../security/overview.md).

## Transaction-store requirements

Implement `OAuthTransactionStore` over shared storage that all application workers can access.
`put()` must enforce the requested TTL. `take()` must atomically compare the supplied browser
session-binding digest and remove the transaction only when the binding matches. It must return
`None` for missing, expired, consumed, or differently bound state. A local in-process dictionary is
not sufficient for restarts or multi-worker deployment and is not included in this package.

Store only the SHA-256 state digest as the lookup key. Bound value size and lifetime, restrict
access to the store, protect the PKCE verifier at rest, and avoid logging keys or transaction
contents. A store outage fails the flow; do not bypass state validation or fall back to weaker
process-local storage.

## Provider and callback configuration

Configure the provider adapter with a fixed client ID, trusted HTTPS authorization endpoint,
issuer, token endpoint, transport timeout, and credentials held outside source control. Register
the exact callback URI with the provider. The app must supply the same client ID to `begin()` and
bind both `begin()` and `complete()` to the same unpredictable browser session value.

At the callback route, pass the original state, authorization code or provider error, and the
server-derived session binding directly to `complete()`. Do not accept both a code and an error,
do not retry a code after state consumption, and do not log callback query parameters. Cancellation
or ambiguous token-exchange failure requires a new login flow.

For OIDC, configure an adapter that performs signature verification and validates trusted issuer
keys, issuer, audience, authorized party, token times, and nonce. The flow rejects OIDC starts when
no verifier is configured. It does not discover keys or instantiate a verifier automatically.

## Failure behavior and observability

Failures use provider-neutral `OAuthFlowError` subclasses. Exchange exceptions and untrusted
provider descriptions are sanitized; callback state and code failures are returned without raw
credential values. Record safe operational metadata such as failure category and correlation ID,
but exclude state, nonce, codes, token values, session bindings, and provider response bodies.

Alert on sustained store errors, provider timeout/error rates, callback failures, and OIDC
verification failures. Avoid recording unbounded user or provider strings as metric labels. Define
timeouts and retry policy in the provider adapter; the capability deliberately does not retry
single-use authorization codes.

## Release validation

Use an isolated identity-provider test tenant to verify exact redirect registration, PKCE S256,
browser binding, denial handling, callback replay rejection, issuer/audience/nonce failures, key
rotation, and provider timeout behavior. Test the actual shared store under concurrent callbacks
and application restarts. Unit tests here use an in-memory test fake and synthetic tokens; they do
not establish store durability, provider interoperability, deployment correctness, or production
readiness.
