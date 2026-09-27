def test_identity_history_unavailable_is_publicly_exported():
    from decent_identity import IdentityHistoryUnavailable
    from decent_identity.identity_resolver import (
        IdentityHistoryUnavailable as ResolverIdentityHistoryUnavailable,
    )

    assert IdentityHistoryUnavailable is ResolverIdentityHistoryUnavailable
