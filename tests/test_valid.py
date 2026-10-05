from secure_record import (
    seal,
    open_record,
    GATEWAY_TO_NODE,
    NODE_TO_GATEWAY,
)


SESSION_ID = b"12345678"

G2N_ENC = b"G" * 32
G2N_MAC = b"M" * 32

N2G_ENC = b"N" * 32
N2G_MAC = b"n" * 32


def test_valid_gateway_to_node():
    record = seal(
        SESSION_ID,
        0,
        1,
        b"Hello Node",
        G2N_ENC,
        G2N_MAC,
        GATEWAY_TO_NODE,
    )

    message_type, plaintext = open_record(
        record,
        SESSION_ID,
        0,
        GATEWAY_TO_NODE,
        G2N_ENC,
        G2N_MAC,
    )

    assert message_type == 1
    assert plaintext == b"Hello Node"


def test_valid_node_to_gateway():
    record = seal(
        SESSION_ID,
        0,
        1,
        b"Hello Gateway",
        N2G_ENC,
        N2G_MAC,
        NODE_TO_GATEWAY,
    )

    message_type, plaintext = open_record(
        record,
        SESSION_ID,
        0,
        NODE_TO_GATEWAY,
        N2G_ENC,
        N2G_MAC,
    )

    assert message_type == 1
    assert plaintext == b"Hello Gateway"

