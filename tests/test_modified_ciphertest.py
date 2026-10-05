import pytest

from secure_record import (
    seal,
    open_record,
    GATEWAY_TO_NODE,
)


def test_modified_ciphertext_rejected():
    session_id = b"12345678"
    key_enc = b"G" * 32
    key_mac = b"M" * 32

    record = seal(
        session_id,
        0,
        1,
        b"Secret message",
        key_enc,
        key_mac,
        GATEWAY_TO_NODE,
    )

    modified = bytearray(record)

    # Header = 15 bytes
    # IV = 16 bytes
    # So byte 31 is the first ciphertext byte.
    modified[31] ^= 0x01

    with pytest.raises(ValueError, match="invalid MAC"):
        open_record(
            bytes(modified),
            session_id,
            0,
            GATEWAY_TO_NODE,
            key_enc,
            key_mac,
        )

