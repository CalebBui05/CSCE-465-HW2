import pytest

from secure_record import (
    seal,
    open_record,
    GATEWAY_TO_NODE,
)


def test_modified_header_rejected():
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

    modified = bytearray(record)

    # Header byte 10 is message_type.
    modified[10] ^= 0x01

    with pytest.raises(ValueError):
        open_record(
            bytes(modified),
            session_id,
            0,
            GATEWAY_TO_NODE,
            key_enc,
            key_mac,
        )

