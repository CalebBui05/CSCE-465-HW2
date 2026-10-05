from handshake import (
    Party,
    load_dh_parameters,
    generate_dh_keypair,
    build_transcript,
    transcript_hash,
    sign_transcript,
    verify_signature,
)


def create_handshake_values():
    gateway = Party("gateway")
    node = Party("node")

    parameters = load_dh_parameters("ffdhe3072.pem")

    gateway.dh_private, gateway.dh_public = (
        generate_dh_keypair(parameters)
    )

    node.dh_private, node.dh_public = (
        generate_dh_keypair(parameters)
    )

    import os

    gateway.nonce = os.urandom(16)
    node.nonce = os.urandom(16)

    transcript = build_transcript(gateway, node)
    TH = transcript_hash(transcript)

    return gateway, node, TH


def test_invalid_rsa_signature_rejected():
    gateway, node, TH = create_handshake_values()

    # Create a legitimate Gateway signature.
    signature = sign_transcript(gateway, TH)

    # Modify one byte of the signature.
    modified_signature = bytearray(signature)
    modified_signature[0] ^= 0x01

    # The modified signature must be rejected.
    assert verify_signature(
        "gateway",
        gateway.public_key,
        TH,
        bytes(modified_signature),
    ) is False

