from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

VERSION = 1

# Direction values
GATEWAY_TO_NODE = 0
NODE_TO_GATEWAY = 1


def seal(
    session_id,
    sequence,
    message_type,
    plaintext,
    key_enc,
    key_mac,
    direction
):
    """
    Create an authenticated encrypted record.

    Format:

        header =
            version(1) ||
            direction(1) ||
            sequence(8) ||
            message_type(1) ||
            ciphertext_length(4)

        iv = session_id(8) || sequence(8)

        ciphertext = AES-256-CTR(key_enc, iv, plaintext)

        tag = HMAC-SHA-256(
            key_mac,
            header || iv || ciphertext
        )
    """

    # AES-256 requires a 32-byte encryption key.
    if len(key_enc) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    # HMAC key should also be 32 bytes from the handshake KDF.
    if len(key_mac) != 32:
        raise ValueError("MAC key must be 32 bytes")

    if len(session_id) != 8:
        raise ValueError("session_id must be 8 bytes")

    if not (0 <= sequence <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("sequence must fit in 8 bytes")

    if not (0 <= message_type <= 0xFF):
        raise ValueError("message_type must fit in 1 byte")

    if direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
        raise ValueError("invalid direction")

    # --------------------------------------------------
    # IV = session_id || sequence
    # --------------------------------------------------

    iv = (
        session_id +
        sequence.to_bytes(8, "big")
    )

    # --------------------------------------------------
    # AES-256-CTR encryption
    # --------------------------------------------------

    cipher = Cipher(
        algorithms.AES(key_enc),
        modes.CTR(iv)
    )

    encryptor = cipher.encryptor()

    ciphertext = (
        encryptor.update(plaintext) +
        encryptor.finalize()
    )

    # --------------------------------------------------
    # Header
    # --------------------------------------------------

    ciphertext_length = len(ciphertext)

    if ciphertext_length > 0xFFFFFFFF:
        raise ValueError("plaintext is too large")

    header = (
        VERSION.to_bytes(1, "big") +
        direction.to_bytes(1, "big") +
        sequence.to_bytes(8, "big") +
        message_type.to_bytes(1, "big") +
        ciphertext_length.to_bytes(4, "big")
    )

    # --------------------------------------------------
    # HMAC
    # --------------------------------------------------

    h = hmac.HMAC(key_mac, hashes.SHA256())

    h.update(header)
    h.update(iv)
    h.update(ciphertext)

    tag = h.finalize()

    # --------------------------------------------------
    # Complete record
    # --------------------------------------------------

    return header + iv + ciphertext + tag
    
def open_record(
    record,
    session_id,
    expected_sequence,
    expected_direction,
    key_enc,
    key_mac
):
    """
    Verify and decrypt one secure record.

    Returns:
        (message_type, plaintext)

    Raises:
        ValueError if the record is invalid.

    Plaintext is never returned after an error.
    """

    # --------------------------------------------------
    # Basic key/session validation
    # --------------------------------------------------

    if len(key_enc) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    if len(key_mac) != 32:
        raise ValueError("MAC key must be 32 bytes")

    if len(session_id) != 8:
        raise ValueError("session_id must be 8 bytes")

    if expected_direction not in (
        GATEWAY_TO_NODE,
        NODE_TO_GATEWAY
    ):
        raise ValueError("invalid expected direction")

    if not (0 <= expected_sequence <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("invalid expected sequence")

    # --------------------------------------------------
    # Minimum record size
    #
    # header = 15 bytes
    # iv     = 16 bytes
    # tag    = 32 bytes
    # --------------------------------------------------

    MIN_RECORD_SIZE = 15 + 16 + 32

    if len(record) < MIN_RECORD_SIZE:
        raise ValueError("record is too short")

    # --------------------------------------------------
    # Parse header
    # --------------------------------------------------

    header = record[:15]

    version = header[0]
    direction = header[1]
    sequence = int.from_bytes(header[2:10], "big")
    message_type = header[10]
    ciphertext_length = int.from_bytes(header[11:15], "big")

    # --------------------------------------------------
    # Validate header BEFORE doing any decryption
    # --------------------------------------------------

    if version != VERSION:
        raise ValueError("unsupported protocol version")

    if direction != expected_direction:
        raise ValueError("wrong record direction")

    if sequence != expected_sequence:
        raise ValueError("unexpected sequence number")

    # --------------------------------------------------
    # Check record length
    #
    # 15-byte header
    # + 16-byte IV
    # + ciphertext
    # + 32-byte HMAC
    # --------------------------------------------------

    expected_length = (
        15 +
        16 +
        ciphertext_length +
        32
    )

    if len(record) != expected_length:
        raise ValueError("invalid record length")

    # --------------------------------------------------
    # Extract IV, ciphertext, and tag
    # --------------------------------------------------

    iv_start = 15
    iv_end = iv_start + 16

    ciphertext_start = iv_end
    ciphertext_end = ciphertext_start + ciphertext_length

    iv = record[iv_start:iv_end]
    ciphertext = record[ciphertext_start:ciphertext_end]
    tag = record[ciphertext_end:]

    # --------------------------------------------------
    # Verify that the IV corresponds to this session
    # and expected sequence.
    # --------------------------------------------------

    expected_iv = (
        session_id +
        expected_sequence.to_bytes(8, "big")
    )

    if iv != expected_iv:
        raise ValueError("invalid IV")

    # --------------------------------------------------
    # Verify HMAC BEFORE decrypting
    # --------------------------------------------------

    h = hmac.HMAC(key_mac, hashes.SHA256())

    h.update(header)
    h.update(iv)
    h.update(ciphertext)

    try:
        h.verify(tag)
    except InvalidSignature:
        raise ValueError("invalid MAC")

    # --------------------------------------------------
    # Only decrypt after successful MAC verification
    # --------------------------------------------------

    cipher = Cipher(
        algorithms.AES(key_enc),
        modes.CTR(iv)
    )

    decryptor = cipher.decryptor()

    plaintext = (
        decryptor.update(ciphertext) +
        decryptor.finalize()
    )

    return message_type, plaintext
