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
"""Regression coverage for secure single-use OAuth and OIDC flows."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import pytest
from orbit_auth import OAuthAuthorizationRequest, OAuthTokenResponse

from orbit_auth_oauth2 import (
    IDTokenClaims,
    OAuth2Flow,
    OAuthAuthorizationDenied,
    OAuthCallbackError,
    OAuthExchangeError,
    OAuthFlowError,
    OAuthTransaction,
)

SESSION_BINDING = "browser-session-" + "a" * 32
OTHER_SESSION_BINDING = "browser-session-" + "b" * 32


class MemoryStore:
    """Atomic single-process fake used only by tests, never advertised as production storage."""

    def __init__(self) -> None:
        self.values: dict[bytes, OAuthTransaction] = {}
        self.lock = asyncio.Lock()

    async def put(self, key: bytes, transaction: OAuthTransaction, *, ttl: int) -> None:
        assert 30 <= ttl <= 1_800
        self.values[key] = transaction

    async def take(self, key: bytes, *, session_binding_hash: bytes) -> OAuthTransaction | None:
        async with self.lock:
            transaction = self.values.get(key)
            if transaction is None or not hmac.compare_digest(
                transaction.session_binding_hash, session_binding_hash
            ):
                return None
            return self.values.pop(key)


class Provider:
    client_id = "web-client"
    authorization_endpoint = "https://id.example/authorize"
    issuer = "https://id.example"

    def __init__(self) -> None:
        self.request: OAuthAuthorizationRequest | None = None
        self.exchange_arguments: tuple[str, str, str | None] | None = None
        self.exchange_error: Exception | None = None
        self.exchange_cancelled = False
        self.id_token: str | None = None

    def authorize_url(self, request: OAuthAuthorizationRequest) -> str:
        self.request = request
        query: dict[str, str] = {
            "client_id": request.client_id,
            "redirect_uri": str(request.redirect_uri),
            "response_type": request.response_type,
            "state": request.state,
            "code_challenge": request.code_challenge or "",
            "code_challenge_method": request.code_challenge_method or "",
        }
        if request.scope:
            query["scope"] = " ".join(sorted(request.scope))
        if request.nonce is not None:
            query["nonce"] = request.nonce
        return "https://id.example/authorize?" + urlencode(query)

    async def exchange_code(
        self, code: str, *, redirect_uri: str, code_verifier: str | None = None
    ) -> OAuthTokenResponse:
        self.exchange_arguments = (code, redirect_uri, code_verifier)
        if self.exchange_cancelled:
            raise asyncio.CancelledError
        if self.exchange_error is not None:
            raise self.exchange_error
        extra = {"id_token": self.id_token} if self.id_token is not None else {}
        return OAuthTokenResponse(access_token="access-secret", expires_in=300, **extra)


class IDVerifier:
    def __init__(
        self,
        *,
        nonce: str | None = None,
        issuer: str = "https://id.example",
        audiences: tuple[str, ...] | None = None,
        authorized_party: str | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        self.nonce = nonce
        self.issuer = issuer
        self.audiences = audiences
        self.authorized_party = authorized_party
        self.expires_at = expires_at

    def verify(self, token: str, *, issuer: str, audience: str, nonce: str) -> IDTokenClaims:
        assert token == "signed-id-token"
        assert issuer == self.issuer
        return IDTokenClaims(
            issuer=self.issuer,
            subject="person-123",
            audiences=self.audiences or (audience,),
            nonce=self.nonce if self.nonce is not None else nonce,
            expires_at=self.expires_at or ID_EXPIRY,
            authorized_party=self.authorized_party,
        )


ID_EXPIRY = datetime.now(UTC) + timedelta(minutes=5)


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def test_begin_generates_strong_state_and_s256_pkce() -> None:
    store = MemoryStore()
    provider = Provider()
    flow = OAuth2Flow(store, transaction_ttl=90)

    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
        scopes={"profile", "openid"},
    )

    request = provider.request
    assert request is not None
    assert 43 <= len(start.state) <= 512
    assert request.state == start.state
    assert request.code_challenge_method == "S256"
    assert request.code_challenge is not None
    assert len(request.code_challenge) == 43
    assert len(store.values) == 1
    transaction = next(iter(store.values.values()))
    assert _pkce_challenge(transaction.code_verifier) == request.code_challenge
    assert start.state not in repr(start)
    assert transaction.code_verifier not in repr(transaction)


async def test_complete_exchanges_once_using_original_redirect_and_pkce_verifier() -> None:
    store = MemoryStore()
    provider = Provider()
    flow = OAuth2Flow(store)
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
    )
    transaction = next(iter(store.values.values()))

    result = await flow.complete(
        provider,
        state=start.state,
        session_binding=SESSION_BINDING,
        code="authorization-code",
    )

    assert result.identity is None
    assert provider.exchange_arguments == (
        "authorization-code",
        "https://app.example/callback",
        transaction.code_verifier,
    )
    assert "access-secret" not in repr(result)
    with pytest.raises(OAuthCallbackError, match="missing, expired, or already consumed"):
        await flow.complete(
            provider,
            state=start.state,
            session_binding=SESSION_BINDING,
            code="authorization-code",
        )


async def test_callback_requires_the_originating_browser_session_without_burning_state() -> None:
    store = MemoryStore()
    provider = Provider()
    flow = OAuth2Flow(store)
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
    )

    with pytest.raises(OAuthCallbackError, match="missing, expired, or already consumed"):
        await flow.complete(
            provider,
            state=start.state,
            session_binding=OTHER_SESSION_BINDING,
            code="authorization-code",
        )
    assert len(store.values) == 1

    result = await flow.complete(
        provider,
        state=start.state,
        session_binding=SESSION_BINDING,
        code="authorization-code",
    )
    assert result.tokens.access_token == "access-secret"


async def test_concurrent_callbacks_consume_state_atomically() -> None:
    store = MemoryStore()
    provider = Provider()
    flow = OAuth2Flow(store)
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
    )

    results = await asyncio.gather(
        flow.complete(provider, state=start.state, session_binding=SESSION_BINDING, code="one"),
        flow.complete(provider, state=start.state, session_binding=SESSION_BINDING, code="two"),
        return_exceptions=True,
    )

    assert sum(isinstance(result, OAuthCallbackError) for result in results) == 1
    assert sum(not isinstance(result, BaseException) for result in results) == 1
    assert provider.exchange_arguments is not None


async def test_callback_rejects_expired_transaction_before_provider_exchange() -> None:
    store = MemoryStore()
    provider = Provider()
    timestamp = [1_000.0]
    flow = OAuth2Flow(store, transaction_ttl=30, clock=lambda: timestamp[0])
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
    )
    timestamp[0] += 31

    with pytest.raises(OAuthCallbackError, match="transaction expired"):
        await flow.complete(
            provider,
            state=start.state,
            session_binding=SESSION_BINDING,
            code="authorization-code",
        )
    assert provider.exchange_arguments is None


async def test_oidc_requires_verifier_and_binds_nonce_issuer_and_audience() -> None:
    store = MemoryStore()
    provider = Provider()
    with pytest.raises(ValueError, match="cryptographic ID-token verifier"):
        await OAuth2Flow(store).begin(
            provider,
            client_id="web-client",
            redirect_uri="https://app.example/callback",
            session_binding=SESSION_BINDING,
            issuer="https://id.example",
        )

    flow = OAuth2Flow(store, id_token_verifier=IDVerifier())
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
        scopes={"openid"},
        issuer="https://id.example",
    )
    assert start.nonce is not None
    provider.id_token = "signed-id-token"

    result = await flow.complete(
        provider,
        state=start.state,
        session_binding=SESSION_BINDING,
        code="authorization-code",
    )

    assert result.identity is not None
    assert result.identity.subject == "person-123"
    assert "person-123" not in repr(result)
    assert "person-123" not in repr(result.identity)

    invalid_verifiers = (
        IDVerifier(nonce="wrong"),
        IDVerifier(audiences=("different-client",)),
        IDVerifier(audiences=("web-client", "another-client")),
        IDVerifier(audiences=("web-client", "another-client"), authorized_party="another-client"),
        IDVerifier(expires_at=datetime.now(UTC) - timedelta(seconds=1)),
    )
    for invalid_verifier in invalid_verifiers:
        invalid_flow = OAuth2Flow(store, id_token_verifier=invalid_verifier)
        invalid_start = await invalid_flow.begin(
            provider,
            client_id="web-client",
            redirect_uri="https://app.example/callback",
            session_binding=SESSION_BINDING,
            scopes={"openid"},
            issuer="https://id.example",
        )
        with pytest.raises(OAuthFlowError, match="claims do not match"):
            await invalid_flow.complete(
                provider,
                state=invalid_start.state,
                session_binding=SESSION_BINDING,
                code="authorization-code",
            )


@pytest.mark.parametrize("scope", ["two words", 'quote"', "backslash\\", "scope-é"])
async def test_oidc_requires_openid_scope_and_scope_tokens_follow_oauth_grammar(scope: str) -> None:
    flow = OAuth2Flow(MemoryStore(), id_token_verifier=IDVerifier())
    provider = Provider()
    with pytest.raises(ValueError, match="openid.*scope"):
        await flow.begin(
            provider,
            client_id="web-client",
            redirect_uri="https://app.example/callback",
            session_binding=SESSION_BINDING,
            scopes={"profile"},
            issuer="https://id.example",
        )
    with pytest.raises(ValueError, match="scope names"):
        await flow.begin(
            provider,
            client_id="web-client",
            redirect_uri="https://app.example/callback",
            session_binding=SESSION_BINDING,
            scopes={scope},
        )


async def test_callback_provider_error_is_sanitized_and_state_is_consumed() -> None:
    store = MemoryStore()
    provider = Provider()
    flow = OAuth2Flow(store)
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
    )

    with pytest.raises(OAuthAuthorizationDenied) as caught:
        await flow.complete(
            provider,
            state=start.state,
            session_binding=SESSION_BINDING,
            error="access_denied",
            error_description="private provider detail and secret",
        )

    assert str(caught.value) == "OAuth authorization was denied (access_denied)."
    assert "private provider detail" not in str(caught.value)
    assert provider.exchange_arguments is None


async def test_provider_exchange_failures_do_not_leak_provider_exception() -> None:
    store = MemoryStore()
    provider = Provider()
    provider.exchange_error = RuntimeError("secret=provider-token response-body")
    flow = OAuth2Flow(store)
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
    )

    with pytest.raises(OAuthExchangeError) as caught:
        await flow.complete(
            provider,
            state=start.state,
            session_binding=SESSION_BINDING,
            code="authorization-code",
        )

    assert str(caught.value) == "OAuth authorization-code exchange failed."
    assert caught.value.__cause__ is None


async def test_code_is_not_retried_after_cancellation() -> None:
    store = MemoryStore()
    provider = Provider()
    provider.exchange_cancelled = True
    flow = OAuth2Flow(store)
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
    )

    with pytest.raises(asyncio.CancelledError):
        await flow.complete(
            provider,
            state=start.state,
            session_binding=SESSION_BINDING,
            code="authorization-code",
        )
    with pytest.raises(OAuthCallbackError, match="missing, expired, or already consumed"):
        await flow.complete(
            provider,
            state=start.state,
            session_binding=SESSION_BINDING,
            code="authorization-code",
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"state": "short", "code": "x"}, "state is invalid"),
        ({"state": "s" * 16, "code": "bad\ncode"}, "authorization code is invalid"),
        ({"state": "s" * 16, "code": "x", "error": "access_denied"}, "both code and error"),
    ],
)
async def test_callback_rejects_malformed_input_before_exchange(kwargs, message: str) -> None:
    store = MemoryStore()
    flow = OAuth2Flow(store)
    provider = Provider()
    start = await flow.begin(
        provider,
        client_id="web-client",
        redirect_uri="https://app.example/callback",
        session_binding=SESSION_BINDING,
    )
    if kwargs["state"] == "s" * 16:
        kwargs["state"] = start.state
    with pytest.raises(OAuthCallbackError, match=message):
        await flow.complete(provider, session_binding=SESSION_BINDING, **kwargs)
    assert provider.exchange_arguments is None


class MalformedProvider(Provider):
    def authorize_url(self, request: OAuthAuthorizationRequest) -> str:
        return "https://id.example/authorize?client_id=attacker&state=" + request.state


class HostSwitchProvider(Provider):
    def authorize_url(self, request: OAuthAuthorizationRequest) -> str:
        return super().authorize_url(request).replace("id.example", "attacker.example")


async def test_provider_must_preserve_all_mandatory_authorization_parameters() -> None:
    store = MemoryStore()
    flow = OAuth2Flow(store)
    with pytest.raises(OAuthFlowError, match="omitted or changed"):
        await flow.begin(
            MalformedProvider(),
            client_id="web-client",
            redirect_uri="https://app.example/callback",
            session_binding=SESSION_BINDING,
        )
    assert store.values == {}


async def test_provider_cannot_redirect_authorization_to_an_unconfigured_host() -> None:
    flow = OAuth2Flow(MemoryStore())
    with pytest.raises(OAuthFlowError, match="configured authorization endpoint"):
        await flow.begin(
            HostSwitchProvider(),
            client_id="web-client",
            redirect_uri="https://app.example/callback",
            session_binding=SESSION_BINDING,
        )


@pytest.mark.parametrize("ttl", [True, 0, 29, 1_801])
def test_transaction_ttl_is_bounded(ttl: int) -> None:
    with pytest.raises((TypeError, ValueError)):
        OAuth2Flow(MemoryStore(), transaction_ttl=ttl)


@pytest.mark.parametrize("binding", ["short", "é" * 32, "x" * 32 + "\n"])
async def test_session_binding_must_be_opaque_bounded_ascii(binding: str) -> None:
    flow = OAuth2Flow(MemoryStore())
    with pytest.raises(ValueError, match="session_binding"):
        await flow.begin(
            Provider(),
            client_id="web-client",
            redirect_uri="https://app.example/callback",
            session_binding=binding,
        )
