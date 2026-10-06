# Orbit Auth OAuth 2.0 and OpenID Connect: operations and security

This guide organizes runtime behavior documented by the package. It does not certify production readiness. Verify provider/client versions, permissions, transport security, limits, and failure behavior in the target environment before release.

## Configuration surface

Environment names found in the package README:

The package README does not name `ORBIT_*` variables. Use its typed constructors and application configuration, and confirm exact runtime inputs in the implementation before deployment.

Use the package README's constructor and deployment examples. Store credentials in a secret manager and avoid logging credentials, raw provider errors, request data, or opaque cursors.

## Lifecycle, failure behavior, and limits

`orbit-auth-oauth2` provides provider-neutral authorization-code flow orchestration over the stable
contracts in `orbit-auth`. It creates cryptographically random state, an OpenID nonce when an
issuer is configured, and an S256 PKCE challenge. It stores the verifier in a short-lived external
transaction store, atomically consumes callback state once, exchanges the authorization code, and
refuses OIDC identity unless a cryptographic ID-token verifier is configured.

```bash
pip install orbit-auth orbit-auth-oauth2
```

## Production validation

Validate startup/shutdown cleanup, timeout and cancellation behavior, concurrency and payload bounds where applicable, secret rotation and least-privilege access, data durability, backup/restore, and failover against the selected provider. Do not infer distributed or durable guarantees from an in-process API or fake-client tests.
