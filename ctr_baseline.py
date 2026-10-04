from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

COMMAND = b'{"action":"READ","path":"notes.txt"}'

#fixed key for lab, changed from random
KEY = b"0123456789abcdef"
NONCE = b"12345678" + b"\x00" * 8


def encrypt(command, key, nonce):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce)
    )
    encryptor = cipher.encryptor()
    return encryptor.update(command) + encryptor.finalize()


def decrypt(ciphertext, key, nonce):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce)
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def relay_modify(ciphertext, old_value=b"READ", new_value=b"LIST"):
    """
    Modify ciphertext without knowing the AES key.

    CTR:
        C = P XOR K

    Therefore:
        C' = C XOR P XOR P'

    The receiver decrypts C' as P'.
    """

    if len(old_value) != len(new_value):
        raise ValueError("Values must have equal length")

    modified = bytearray(ciphertext)

    offset = COMMAND.find(old_value)

    if offset == -1:
        raise ValueError("Original value not found")

    print("\nXOR relation between original and modified bytes:")
    print("Original: ", old_value)
    print("Modified: ", new_value)

    for i in range(len(old_value)):
        xor_value = old_value[i] ^ new_value[i]

        print(
            f"{old_value[i]:02x} XOR {new_value[i]:02x}"
            f" = {xor_value:02x}"
        )

        modified[offset + i] ^= xor_value

    return bytes(modified)


#sender
ciphertext = encrypt(COMMAND, KEY, NONCE)

print("Original plaintext:")
print(COMMAND.decode())

print("\nCiphertext:")
print(ciphertext.hex())


#relay
modified_ciphertext = relay_modify(
    ciphertext,
    old_value=b"READ",
    new_value=b"LIST"
)


#receiver
modified_plaintext = decrypt(
    modified_ciphertext,
    KEY,
    NONCE
)

print("\nModified plaintext:")
print(modified_plaintext.decode())


#replay
print("\nReplay demonstration:")

first = decrypt(ciphertext, KEY, NONCE)
second = decrypt(ciphertext, KEY, NONCE)

print("First time receiver processes:")
print(first.decode())

print("\nSecond time receiver processes the SAME ciphertext:")
print(second.decode())