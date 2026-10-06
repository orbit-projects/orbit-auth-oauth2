# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Bounded authorization-code flow orchestration over Orbit Core provider contracts."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import math
import secrets
import time
from collections.abc import Awaitable, Callable, Collection
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable
from urllib.parse import parse_qs, urlsplit

from orbit_auth import (
    OAuthAuthorizationRequest,
    OAuthProvider,
    OAuthTokenResponse,
    is_https_url,
)

_MIN_TTL_SECONDS = 30
_MAX_TTL_SECONDS = 1_800
_MAX_AUTHORIZATION_URL_LENGTH = 8_192
_MAX_CODE_LENGTH = 8_192
_MAX_ERROR_LENGTH = 255
_MAX_SCOPES = 1_024
_MAX_SUBJECT_LENGTH = 255


class OAuthFlowError(Exception):
    """Base class for safe, provider-neutral OAuth flow failures."""


class OAuthCallbackError(OAuthFlowError):
    """Callback state, shape, or one-time transaction validation failed."""


class OAuthAuthorizationDenied(OAuthFlowError):
    """The authorization server denied the request; provider text is not retained."""

    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__(f"OAuth authorization was denied ({error}).")


class OAuthExchangeError(OAuthFlowError):
    """The provider rejected or failed the authorization-code exchange."""


@dataclass(frozen=True, slots=True, repr=False)
class OAuthTransaction:
    """One short-lived, single-use login transaction; secret fields are omitted from repr."""

    client_id: str = field(repr=False)
    redirect_uri: str = field(repr=False)
    authorization_endpoint: str = field(repr=False)
    state: str = field(repr=False)
    session_binding_hash: bytes = field(repr=False)
    nonce: str | None = field(repr=False)
    code_verifier: str = field(repr=False)
    provider_issuer: str | None = field(repr=False)
    expires_at: float
    issuer: str | None = None

    def __repr__(self) -> str:
        return (
            "OAuthTransaction(client_id=[REDACTED], redirect_uri=[REDACTED], "
            "state=[REDACTED], nonce=[REDACTED], code_verifier=[REDACTED], "
            f"expires_at={self.expires_at!r}, issuer={self.issuer!r})"
        )


@runtime_checkable
class OAuthTransactionStore(Protocol):
    """External state store contract; ``take`` must atomically read and delete a key.

    Store only the supplied SHA-256 digest as the key. Implementations must enforce the requested
    TTL, bound stored values, protect the PKCE verifier at rest, and make ``take`` atomically
    compare the browser-session binding and consume a transaction across workers. This package
    deliberately provides no process-local store because it would lose
    transactions on restart and break multi-worker deployments.
    """

    async def put(self, key: bytes, transaction: OAuthTransaction, *, ttl: int) -> None:
        """Persist one transaction under its opaque digest, with an expiry no longer than TTL."""

    async def take(self, key: bytes, *, session_binding_hash: bytes) -> OAuthTransaction | None:
        """Atomically consume a transaction only when its browser-session binding matches.

        A missing, expired, consumed, or differently bound transaction returns ``None`` without
        deleting a transaction belonging to another browser session.
        """


@runtime_checkable
class OAuth2Provider(OAuthProvider, Protocol):
    """Provider-adapter contract extending Core with explicit trusted endpoint configuration."""

    client_id: str
    authorization_endpoint: str
    issuer: str | None


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationStart:
    """Authorization redirect and browser state; state is intentionally redacted from repr."""

    authorization_url: str = field(repr=False)
    state: str = field(repr=False)
    nonce: str | None = field(repr=False)

    def __repr__(self) -> str:
        return (
            "AuthorizationStart(authorization_url=[REDACTED], state=[REDACTED], nonce=[REDACTED])"
        )


@dataclass(frozen=True, slots=True, repr=False)
class IDTokenClaims:
    """Claims returned only after an adapter has cryptographically verified an OIDC ID token.

    ``IDTokenVerifier`` implementations must check the signature against trusted issuer keys and
    validate ``iss``, ``aud``, ``azp``, ``exp``, ``iat``, ``nbf`` when present, and the supplied
    nonce. The flow repeats audience, issuer, expiry, and nonce checks against its transaction.
    """

    issuer: str
    subject: str
    audiences: tuple[str, ...]
    nonce: str
    expires_at: datetime
    authorized_party: str | None = None

    def __repr__(self) -> str:
        """Keep personal identity values and the nonce out of diagnostic representations."""
        return "IDTokenClaims(issuer=[REDACTED], subject=[REDACTED], identity_claims=[REDACTED])"


@runtime_checkable
class IDTokenVerifier(Protocol):
    """Provider adapter contract for issuer-key discovery and cryptographic ID-token validation."""

    def verify(
        self,
        token: str,
        *,
        issuer: str,
        audience: str,
        nonce: str,
    ) -> IDTokenClaims | Awaitable[IDTokenClaims]:
        """Validate a signed OIDC ID token and return detached, verified standard claims."""


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationResult:
    """Exchanged OAuth tokens and optional verified OIDC identity, with token repr redacted."""

    tokens: OAuthTokenResponse = field(repr=False)
    identity: IDTokenClaims | None

    def __repr__(self) -> str:
        verified = self.identity is not None
        return f"AuthorizationResult(tokens=[REDACTED], verified_oidc_identity={verified})"


class OAuth2Flow:
    """Coordinate one-time OAuth authorization-code flows without owning storage or HTTP.

    The provider adapter supplies endpoints, transport, provider credentials and error mapping.
    The application supplies a shared transaction store whose ``take`` operation is atomic.
    Tokens are never logged by this package; an exchange error is replaced with a generic typed
    error so provider libraries cannot leak response bodies, credentials, or authorization codes.
    """

    def __init__(
        self,
        store: OAuthTransactionStore,
        *,
        id_token_verifier: IDTokenVerifier | None = None,
        transaction_ttl: int = 600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(store, OAuthTransactionStore):
            raise TypeError("store must implement async put() and atomic take().")
        if isinstance(transaction_ttl, bool) or not isinstance(transaction_ttl, int):
            raise TypeError("transaction_ttl must be an integer number of seconds.")
        if not _MIN_TTL_SECONDS <= transaction_ttl <= _MAX_TTL_SECONDS:
            raise ValueError(
                "transaction_ttl must be between "
                f"{_MIN_TTL_SECONDS} and {_MAX_TTL_SECONDS} seconds."
            )
        if not callable(clock):
            raise TypeError("clock must be callable and return a finite Unix timestamp.")
        self._store = store
        self._id_token_verifier = id_token_verifier
        self._ttl = transaction_ttl
        self._clock = clock

    async def begin(
        self,
        provider: OAuth2Provider,
        *,
        client_id: str,
        redirect_uri: str,
        session_binding: str,
        scopes: Collection[str] = (),
        issuer: str | None = None,
    ) -> AuthorizationStart:
        """Create a PKCE S256 authorization request and persist its single-use transaction.

        Set ``issuer`` to request OIDC, which adds a cryptographic nonce. OIDC is refused unless
        an ID-token verifier was configured; OAuth tokens are never treated as authenticated
        identity on their own.
        """
        endpoint = _validate_provider(provider)
        if provider.client_id != client_id:
            raise ValueError("client_id must match the configured OAuth provider adapter.")
        if issuer is not None:
            if (
                not isinstance(issuer, str)
                or not is_https_url(issuer)
                or bool(urlsplit(issuer).query)
            ):
                raise ValueError(
                    "OIDC issuer must be a valid HTTPS URL (localhost is allowed for dev)."
                )
            if self._id_token_verifier is None:
                raise ValueError("OIDC requires a configured cryptographic ID-token verifier.")
            if provider.issuer != issuer:
                raise ValueError("OIDC issuer must match the configured OAuth provider adapter.")
        normalized_scopes = _validate_scopes(scopes)
        binding_hash = _binding_digest(session_binding)
        if issuer is not None and "openid" not in normalized_scopes:
            raise ValueError("OpenID Connect requests must include the 'openid' scope.")
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32) if issuer is not None else None
        verifier = secrets.token_urlsafe(32)
        challenge = _base64url(hashlib.sha256(verifier.encode("ascii")).digest())
        request = OAuthAuthorizationRequest.model_validate(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": normalized_scopes,
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        try:
            authorization_url = provider.authorize_url(request)
            if inspect.isawaitable(authorization_url):
                authorization_url = await authorization_url
            _validate_authorization_url(authorization_url, request, endpoint=endpoint)
            now = _now(self._clock)
            transaction = OAuthTransaction(
                client_id=request.client_id,
                redirect_uri=str(request.redirect_uri),
                authorization_endpoint=endpoint,
                state=state,
                session_binding_hash=binding_hash,
                nonce=nonce,
                code_verifier=verifier,
                provider_issuer=provider.issuer,
                expires_at=now + self._ttl,
                issuer=issuer,
            )
            await self._store.put(_state_key(state), transaction, ttl=self._ttl)
        except asyncio.CancelledError:
            raise
        except OAuthFlowError:
            raise
        except Exception:
            raise OAuthFlowError("Could not start the OAuth authorization flow.") from None
        return AuthorizationStart(authorization_url, state, nonce)

    async def complete(
        self,
        provider: OAuth2Provider,
        *,
        state: str,
        session_binding: str,
        code: str | None = None,
        error: str | None = None,
        error_description: str | None = None,
    ) -> AuthorizationResult:
        """Consume the callback state once, exchange the code, and verify OIDC identity if used.

        Authorization codes are not retried: cancellation or network failure after consumption
        requires the caller to start a new authorization transaction. Provider error descriptions
        are intentionally ignored because they are untrusted and may contain sensitive text.
        """
        del error_description
        _validate_state(state)
        binding_hash = _binding_digest(session_binding)
        endpoint = _validate_provider(provider)
        try:
            transaction = await self._store.take(
                _state_key(state), session_binding_hash=binding_hash
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OAuthCallbackError("Could not load the pending OAuth transaction.") from None
        if not isinstance(transaction, OAuthTransaction):
            raise OAuthCallbackError("OAuth state is missing, expired, or already consumed.")
        if not hmac.compare_digest(transaction.state, state):
            raise OAuthCallbackError("OAuth state did not match the pending transaction.")
        now = _now(self._clock)
        if transaction.expires_at <= now:
            raise OAuthCallbackError("OAuth transaction expired.")
        if (
            provider.client_id != transaction.client_id
            or endpoint != transaction.authorization_endpoint
            or provider.issuer != transaction.provider_issuer
            or (transaction.issuer is not None and provider.issuer != transaction.issuer)
        ):
            raise OAuthCallbackError(
                "OAuth callback provider does not match the pending transaction."
            )
        if error is not None:
            if code is not None:
                raise OAuthCallbackError("OAuth callback cannot contain both code and error.")
            normalized_error = _validate_error_code(error)
            raise OAuthAuthorizationDenied(normalized_error)
        code = _validate_code(code)
        try:
            tokens = provider.exchange_code(
                code,
                redirect_uri=transaction.redirect_uri,
                code_verifier=transaction.code_verifier,
            )
            if inspect.isawaitable(tokens):
                tokens = await tokens
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OAuthExchangeError("OAuth authorization-code exchange failed.") from None
        if not isinstance(tokens, OAuthTokenResponse):
            raise OAuthExchangeError("OAuth provider returned an invalid token response.")
        identity = None
        if transaction.issuer is not None:
            identity = await self._verify_identity(tokens, transaction)
        return AuthorizationResult(tokens=tokens, identity=identity)

    async def _verify_identity(
        self, tokens: OAuthTokenResponse, transaction: OAuthTransaction
    ) -> IDTokenClaims:
        """Require a provider-verified ID token and bind its claims to this login transaction."""
        if (
            self._id_token_verifier is None
            or transaction.issuer is None
            or transaction.nonce is None
        ):
            raise OAuthFlowError("OIDC verifier configuration is incomplete.")
        extra = tokens.model_extra or {}
        id_token = extra.get("id_token")
        if (
            not isinstance(id_token, str)
            or not 1 <= len(id_token) <= 16_384
            or _has_control(id_token)
        ):
            raise OAuthFlowError("OAuth provider did not return a valid OpenID ID token.")
        try:
            claims = self._id_token_verifier.verify(
                id_token,
                issuer=transaction.issuer,
                audience=transaction.client_id,
                nonce=transaction.nonce,
            )
            if inspect.isawaitable(claims):
                claims = await claims
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OAuthFlowError("OpenID ID-token verification failed.") from None
        if not isinstance(claims, IDTokenClaims):
            raise OAuthFlowError("OpenID verifier returned invalid verified claims.")
        if (
            not isinstance(claims.expires_at, datetime)
            or claims.expires_at.tzinfo is None
            or claims.expires_at.utcoffset() is None
        ):
            raise OAuthFlowError("OpenID verifier returned an invalid expiry.")
        try:
            expiry = claims.expires_at.timestamp()
        except (AttributeError, OverflowError, OSError, ValueError):
            raise OAuthFlowError("OpenID verifier returned an invalid expiry.") from None
        if (
            not isinstance(claims.issuer, str)
            or claims.issuer != transaction.issuer
            or not isinstance(claims.subject, str)
            or not 1 <= len(claims.subject) <= _MAX_SUBJECT_LENGTH
            or _has_control(claims.subject)
            or not isinstance(claims.audiences, tuple)
            or not claims.audiences
            or len(claims.audiences) > 32
            or any(
                not isinstance(audience, str)
                or not 1 <= len(audience) <= 255
                or _has_control(audience)
                for audience in claims.audiences
            )
            or len(claims.audiences) != len(set(claims.audiences))
            or transaction.client_id not in claims.audiences
            or (len(claims.audiences) > 1 and claims.authorized_party != transaction.client_id)
            or (
                claims.authorized_party is not None
                and claims.authorized_party != transaction.client_id
            )
            or not isinstance(claims.nonce, str)
            or not claims.nonce.isascii()
            or not hmac.compare_digest(claims.nonce, transaction.nonce)
            or not math.isfinite(expiry)
            or expiry <= _now(self._clock)
        ):
            raise OAuthFlowError("OpenID ID-token claims do not match the pending transaction.")
        return claims


def _validate_provider(provider: object) -> str:
    """Require an adapter with fixed client and HTTPS endpoint configuration."""
    if not isinstance(provider, OAuth2Provider):
        raise TypeError(
            "provider must implement Orbit's OAuth provider methods and declare "
            "client_id, authorization_endpoint, and issuer."
        )
    endpoint = provider.authorization_endpoint
    if not isinstance(endpoint, str) or not is_https_url(endpoint):
        raise ValueError("OAuth provider authorization_endpoint must be a trusted HTTPS URL.")
    if urlsplit(endpoint).query:
        raise ValueError("OAuth provider authorization_endpoint must not contain a query.")
    if (
        not isinstance(provider.client_id, str)
        or not 1 <= len(provider.client_id) <= 255
        or _has_control(provider.client_id)
    ):
        raise ValueError("OAuth provider client_id must be bounded, nonempty text.")
    if provider.issuer is not None and (
        not isinstance(provider.issuer, str)
        or not is_https_url(provider.issuer)
        or bool(urlsplit(provider.issuer).query)
    ):
        raise ValueError("OAuth provider issuer must be a valid HTTPS issuer URL.")
    return endpoint


def _validate_authorization_url(
    value: object, request: OAuthAuthorizationRequest, *, endpoint: str
) -> None:
    """Ensure provider adapters preserve mandatory request protections in the redirect URL."""
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_AUTHORIZATION_URL_LENGTH:
        raise OAuthFlowError("OAuth provider returned an invalid authorization URL.")
    if not is_https_url(value):
        raise OAuthFlowError(
            "OAuth authorization URL must use HTTPS (localhost is allowed for dev)."
        )
    parsed = urlsplit(value)
    expected_endpoint = urlsplit(endpoint)
    if parsed.fragment:
        raise OAuthFlowError("OAuth authorization URL must not contain a fragment.")
    if (
        parsed.scheme != expected_endpoint.scheme
        or parsed.hostname != expected_endpoint.hostname
        or parsed.port != expected_endpoint.port
        or (parsed.path or "/") != (expected_endpoint.path or "/")
    ):
        raise OAuthFlowError("OAuth provider changed its configured authorization endpoint.")
    try:
        values = parse_qs(
            parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=64
        )
    except (ValueError, UnicodeError):
        raise OAuthFlowError("OAuth provider returned an invalid authorization URL.") from None
    expected = {
        "client_id": request.client_id,
        "redirect_uri": str(request.redirect_uri),
        "response_type": "code",
        "state": request.state,
        "code_challenge": request.code_challenge,
        "code_challenge_method": "S256",
    }
    if request.scope:
        expected["scope"] = " ".join(sorted(request.scope))
    if request.nonce is not None:
        expected["nonce"] = request.nonce
    for key, expected_value in expected.items():
        items = values.get(key)
        if not isinstance(expected_value, str) or items != [expected_value]:
            raise OAuthFlowError(
                "OAuth provider omitted or changed a required authorization parameter."
            )


def _validate_scopes(scopes: Collection[str]) -> frozenset[str]:
    """Normalize bounded OAuth scope names without splitting or silently coercing input."""
    if isinstance(scopes, (str, bytes)) or not isinstance(scopes, Collection):
        raise TypeError("scopes must be a collection of individual scope names.")
    if len(scopes) > _MAX_SCOPES:
        raise ValueError(f"OAuth requests cannot contain more than {_MAX_SCOPES:,} scopes.")
    result: set[str] = set()
    for scope in scopes:
        if (
            not isinstance(scope, str)
            or not 1 <= len(scope) <= 255
            or any(
                not (
                    ord(character) == 0x21
                    or 0x23 <= ord(character) <= 0x5B
                    or 0x5D <= ord(character) <= 0x7E
                )
                for character in scope
            )
        ):
            raise ValueError(
                "OAuth scope names must be bounded printable tokens without whitespace."
            )
        result.add(scope)
    return frozenset(result)


def _validate_state(state: str) -> None:
    """Bound callback state before hashing or reaching storage."""
    if not isinstance(state, str) or not 16 <= len(state) <= 512 or _has_control(state):
        raise OAuthCallbackError("OAuth callback state is invalid.")


def _validate_code(code: str | None) -> str:
    """Reject absent, oversized, or control-bearing codes before provider transport."""
    if not isinstance(code, str) or not 1 <= len(code) <= _MAX_CODE_LENGTH or _has_control(code):
        raise OAuthCallbackError("OAuth callback authorization code is invalid.")
    return code


def _validate_error_code(error: str) -> str:
    """Retain only a bounded OAuth error identifier, never provider-supplied descriptions."""
    if (
        not isinstance(error, str)
        or not 1 <= len(error) <= _MAX_ERROR_LENGTH
        or any(
            not (character.isascii() and (character.isalnum() or character in "._-"))
            for character in error
        )
    ):
        raise OAuthCallbackError("OAuth callback error code is invalid.")
    return error


def _state_key(state: str) -> bytes:
    """Hash high-entropy state before it becomes a database/cache key."""
    return hashlib.sha256(state.encode("ascii")).digest()


def _binding_digest(session_binding: str) -> bytes:
    """Validate and hash a high-entropy browser session binding before it reaches storage."""
    if (
        not isinstance(session_binding, str)
        or not 32 <= len(session_binding) <= 512
        or not session_binding.isascii()
        or _has_control(session_binding)
    ):
        raise ValueError("session_binding must be 32 to 512 printable ASCII characters.")
    return hashlib.sha256(session_binding.encode("ascii")).digest()


def _base64url(value: bytes) -> str:
    """Encode an RFC 7636 SHA-256 challenge without padding."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _has_control(value: str) -> bool:
    """Return whether text contains ASCII controls or DEL."""
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _now(clock: Callable[[], float]) -> float:
    """Read the injected clock and reject invalid values before evaluating transaction expiry."""
    try:
        value = clock()
    except Exception:
        raise OAuthFlowError("OAuth clock could not provide the current time.") from None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise OAuthFlowError("OAuth clock must return a finite Unix timestamp.")
    return float(value)


__all__ = [
    "AuthorizationResult",
    "AuthorizationStart",
    "IDTokenClaims",
    "IDTokenVerifier",
    "OAuth2Flow",
    "OAuthAuthorizationDenied",
    "OAuthCallbackError",
    "OAuthExchangeError",
    "OAuthFlowError",
    "OAuthTransaction",
    "OAuthTransactionStore",
]
