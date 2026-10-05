import pytest

from secure_record import (
    seal,
    open_record,
    GATEWAY_TO_NODE,
    NODE_TO_GATEWAY,
)


def test_reflected_record_rejected():
    session_id = b"12345678"

    gateway_enc = b"G" * 32
    gateway_mac = b"M" * 32

    node_enc = b"N" * 32
    node_mac = b"n" * 32

    # Gateway creates a Gateway -> Node record.
    record = seal(
        session_id,
        0,
        1,
        b"Hello Node",
        gateway_enc,
        gateway_mac,
        GATEWAY_TO_NODE,
    )

    # Attacker reflects it toward the Gateway as if it
    # were a Node -> Gateway message.
    with pytest.raises(
        ValueError,
        match="wrong record direction"
    ):
        open_record(
            record,
            session_id,
            0,
            NODE_TO_GATEWAY,
            node_enc,
            node_mac,
        )

