# Orbit Auth OAuth 2.0 and OpenID Connect: architecture and boundaries

## Responsibility

`orbit-auth-oauth2` provides provider-neutral authorization-code flow orchestration over the stable
contracts in `orbit-auth`. It creates cryptographically random state, an OpenID nonce when an
issuer is configured, and an S256 PKCE challenge. It stores the verifier in a short-lived external
transaction store, atomically consumes callback state once, exchanges the authorization code, and
refuses OIDC identity unless a cryptographic ID-token verifier is configured.

```bash
pip install orbit-auth orbit-auth-oauth2
```

## Declared dependencies

The following dependency declarations come from the checked-in manifests. Optional groups and development dependencies are called out separately.

### `pyproject.toml`
- `orbit-auth>=0.1.0a1,<0.2`
- Optional `dev` group: `pytest>=8,<10`, `pytest-asyncio>=0.24,<2`, `ruff>=0.8,<1`, `mypy>=1.13,<2`.

Declared dependencies do not mean that optional providers or services are bundled with this package.

## Implementation layout

Representative implementation files in this checkout:

- `src/orbit_auth_oauth2/__init__.py`
- `src/orbit_auth_oauth2/flow.py`

## Flow and trust boundaries

The application owns the HTTP routes and browser session. The capability owns protocol-neutral
state validation, PKCE construction, callback sequencing, and OIDC claim binding. The provider
adapter owns provider endpoints, credentials, HTTP transport, token exchange, and cryptographic
ID-token verification. The transaction store is an application-supplied shared persistence
boundary.

### Starting authorization

1. The application passes a configured provider, exact client ID and redirect URI, scopes, and a
   high-entropy session binding to `begin()`.
2. The capability generates random state and PKCE verifier values. For OIDC it also generates a
   nonce, requires the `openid` scope, and requires an ID-token verifier to be configured.
3. The provider adapter builds the authorization URL. The capability checks HTTPS, endpoint
   identity, and that the adapter preserved every required parameter.
4. The capability stores the transaction under a SHA-256 digest of state with the configured TTL.
   The application returns the checked authorization URL to the browser.

### Completing authorization

1. The application passes callback state, code or denial, and the original server-derived session
   binding to `complete()`.
2. The store atomically compares the binding and consumes the transaction once. A binding mismatch
   must leave the transaction available to the initiating browser.
3. The capability verifies transaction expiry and provider configuration, then exchanges the code
   with the original redirect URI and PKCE verifier. It never retries a consumed code.
4. For OIDC, the adapter cryptographically verifies the ID token. The capability checks the returned
   issuer, audience, authorized party, expiry, and nonce against the stored login transaction.

`complete()` consumes state before exchanging the authorization code. Cancellation or network
failure after consumption therefore requires a new flow; this avoids replaying a code whose
exchange outcome may be ambiguous. Provider network timeouts are controlled by the adapter because
the capability makes no network requests itself.

## Contract references

The [package README](../../README.md) documents installation, composition, storage requirements,
and release limitations. The [security guide](../security/overview.md) documents the threat
boundaries and deployment responsibilities. Public Python contracts are in
`src/orbit_auth_oauth2/flow.py`; they supplement, rather than replace, the behavioral guides.
