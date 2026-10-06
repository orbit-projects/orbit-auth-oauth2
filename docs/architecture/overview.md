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

## Public contract and scope

The README does not contain a separately headed architecture section. Its responsibility statement above and the public source files define the implemented scope; this guide adds no behavior beyond that description.

## Boundary rules

Keep provider SDKs, credentials, transports, and provider-specific error translation in provider adapters. Keep reusable capability contracts in the matching capability package and lifecycle orchestration in Core. Apply the relevant layer for this repository and preserve the dependency direction shown above.
