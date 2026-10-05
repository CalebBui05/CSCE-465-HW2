import pytest

from secure_record import (
    seal,
    open_record,
    GATEWAY_TO_NODE,
)


def test_replayed_record_rejected():
    session_id = b"12345678"
    key_enc = b"G" * 32
    key_mac = b"M" * 32

    record = seal(
        session_id,
        0,
        1,
        b"Hello",
        key_enc,
        key_mac,
        GATEWAY_TO_NODE,
    )

    # First delivery succeeds.
    message_type, plaintext = open_record(
        record,
        session_id,
        0,
        GATEWAY_TO_NODE,
        key_enc,
        key_mac,
    )

    assert plaintext == b"Hello"

    # Same record is replayed.
    # Receiver now expects sequence 1.
    with pytest.raises(
        ValueError,
        match="unexpected sequence number"
    ):
        open_record(
            record,
            session_id,
            1,
            GATEWAY_TO_NODE,
            key_enc,
            key_mac,
        )

