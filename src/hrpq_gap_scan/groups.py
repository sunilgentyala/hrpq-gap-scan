"""Known TLS 1.3 key-agreement group names, classical and post-quantum hybrid."""

# Hybrid groups combining a classical ECDH curve with an ML-KEM (or draft Kyber)
# component. Names as reported by OpenSSL 3.2+ and BoringSSL.
PQ_HYBRID_GROUPS = {
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "X25519Kyber768Draft00",  # pre-standardization draft name, still seen in the wild
}

# Classical-only groups. A handshake landing here when a PQ hybrid group was
# offered means a silent downgrade occurred.
CLASSICAL_GROUPS = {
    "X25519",
    "secp256r1",
    "prime256v1",
    "secp384r1",
    "secp521r1",
}

# Groups actually passed to `openssl s_client -groups`. OpenSSL's SSL_CONF_cmd
# rejects the entire -groups list if it contains a single name the local build
# doesn't recognize, so the legacy pre-standardization draft name
# (X25519Kyber768Draft00) is deliberately excluded here even though it's still
# tracked in PQ_HYBRID_GROUPS for classifying a negotiated result if one is ever
# reported. PQ hybrids are listed first so a successful handshake reflects the
# server's actual best-supported group rather than whatever OpenSSL would pick
# by default.
OFFERABLE_PQ_HYBRID_GROUPS = tuple(
    g for g in PQ_HYBRID_GROUPS if g != "X25519Kyber768Draft00"
)
DEFAULT_GROUP_PREFERENCE = OFFERABLE_PQ_HYBRID_GROUPS + tuple(CLASSICAL_GROUPS)


def is_pq_hybrid(group_name: str | None) -> bool:
    return group_name in PQ_HYBRID_GROUPS
