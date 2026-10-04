import os
import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


class Party:
    def __init__(self, identity):
        self.identity = identity

        # long term RSA signing key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )

        self.public_key = self.private_key.public_key()



#load ffdhe3072 parameters

def load_dh_parameters(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_parameters(f.read())



# generate an ephemeral dh key pair

def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return private_key, public_key



# encode one transcript field
# 4-byte big-endian length || field

def encode_field(field):
    if not isinstance(field, bytes):
        raise TypeError("Transcript fields must be bytes")

    return len(field).to_bytes(4, "big") + field



# Encode DH public value

def encode_dh_public(public_key):
    value = public_key.public_numbers().y

    return value.to_bytes(384, "big")



# Build canonical transcript

#   1. protocol label
#   2. group identifier
#   3. gateway identity
#   4. node identity
#   5. gateway DH public value
#   6. node DH public value
#   7. gateway nonce
#   8. node nonce

def build_transcript(gateway, node):

    fields = [
        b"CSCE465-HS-v2",
        b"ffdhe3072",
        gateway.identity.encode("utf-8"),
        node.identity.encode("utf-8"),
        encode_dh_public(gateway.dh_public),
        encode_dh_public(node.dh_public),
        gateway.nonce,
        node.nonce,
    ]

    transcript = b""

    for field in fields:
        transcript += encode_field(field)

    return transcript



# Validate the transcript encoding

def validate_transcript(transcript):

    fields = []
    position = 0

    while position < len(transcript):

        # Need 4 bytes for the field length
        if position + 4 > len(transcript):
            raise ValueError("Malformed transcript length field")

        field_length = int.from_bytes(
            transcript[position:position + 4],
            "big"
        )

        position += 4

        # declared field must fit inside transcript
        if position + field_length > len(transcript):
            raise ValueError("Declared field length exceeds transcript")

        field = transcript[
            position:position + field_length
        ]

        fields.append(field)

        position += field_length


    if len(fields) != 8:
        raise ValueError("Transcript must contain exactly 8 fields")

    # Validate expected fixed-size fields
    if len(fields[4]) != 384:
        raise ValueError("Gateway DH public value must be 384 bytes")

    if len(fields[5]) != 384:
        raise ValueError("Node DH public value must be 384 bytes")

    if len(fields[6]) != 16:
        raise ValueError("Gateway nonce must be 16 bytes")

    if len(fields[7]) != 16:
        raise ValueError("Node nonce must be 16 bytes")

    # Validate protocol and group
    if fields[0] != b"CSCE465-HS-v2":
        raise ValueError("Unexpected protocol label")

    if fields[1] != b"ffdhe3072":
        raise ValueError("Unexpected DH group")

    return fields



# Transcript hash
# TH = SHA-256(transcript)

def transcript_hash(transcript):

    # Validate before hashing
    validate_transcript(transcript)

    return hashlib.sha256(transcript).digest()



# RSA-PSS signature
# Sign:
# role || TH

def sign_transcript(party, TH):

    role = party.identity.encode("utf-8")

    message = role + TH

    signature = party.private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


# verify RSA-PSS signature

def verify_signature(
    expected_identity,
    peer_public_key,
    TH,
    signature
):

    role = expected_identity.encode("utf-8")

    message = role + TH

    try:
        peer_public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception:
        return False



# dh shared secret
# Both parties independently calculate the same Z.

def derive_shared_secret(private_key, peer_public_key):

    Z = private_key.exchange(peer_public_key)

    # ffdhe3072 produces a 384-byte shared secret.
    if len(Z) != 384:
        raise ValueError("DH shared secret must be 384 bytes")

    return Z



#KDF

def derive_session_keys(Z, TH):

    if len(Z) != 384:
        raise ValueError("Z must be exactly 384 bytes")

    # K_master =
    # SHA-256("CSCE465-KDF-v1" || Z || TH)

    K_master = hashlib.sha256(
        b"CSCE465-KDF-v1" +
        Z +
        TH
    ).digest()

    # Gateway -> Node encryption
    K_g2n_enc = hmac.new(
        K_master,
        b"gateway-to-node encryption" + TH,
        hashlib.sha256
    ).digest()

    # Gateway -> Node MAC
    K_g2n_mac = hmac.new(
        K_master,
        b"gateway-to-node MAC" + TH,
        hashlib.sha256
    ).digest()

    # Node -> Gateway encryption
    K_n2g_enc = hmac.new(
        K_master,
        b"node-to-gateway encryption" + TH,
        hashlib.sha256
    ).digest()

    # Node -> Gateway MAC
    K_n2g_mac = hmac.new(
        K_master,
        b"node-to-gateway MAC" + TH,
        hashlib.sha256
    ).digest()

    # session identifier
    session_id = hmac.new(
        K_master,
        b"session identifier" + TH,
        hashlib.sha256
    ).digest()[:8]

    return (
        K_master,
        K_g2n_enc,
        K_g2n_mac,
        K_n2g_enc,
        K_n2g_mac,
        session_id
    )



# Main handshake

def run_handshake(gateway, node, parameters):

    print("\n--- Starting handshake ---")

    #fresh DH keys for this session
    gateway.dh_private, gateway.dh_public = (
        generate_dh_keypair(parameters)
    )

    node.dh_private, node.dh_public = (
        generate_dh_keypair(parameters)
    )

    # Fresh 16-byte nonces
    gateway.nonce = os.urandom(16)
    node.nonce = os.urandom(16)

    # build canonical transcript
    transcript = build_transcript(
        gateway,
        node
    )

    # Validate before hashing
    validate_transcript(transcript)


    # Calculate TH

    TH = transcript_hash(transcript)

    print("Transcript hash:")
    print(TH.hex())


    # Gateway signs gateway || TH

    gateway_signature = sign_transcript(
        gateway,
        TH
    )

    # Node signs node || TH
    node_signature = sign_transcript(
        node,
        TH
    )

    # Node verifies Gateway signature
    gateway_valid = verify_signature(
        "gateway",
        gateway.public_key,
        TH,
        gateway_signature
    )

    if not gateway_valid:
        raise ValueError(
            "Node rejected Gateway signature"
        )

    print("Node verified Gateway signature.")


    #gateway verifies Node signature
    node_valid = verify_signature(
        "node",
        node.public_key,
        TH,
        node_signature
    )

    if not node_valid:
        raise ValueError(
            "Gateway rejected Node signature"
        )

    print("Gateway verified Node signature.")

    #calculate dh shared secret

    gateway_Z = derive_shared_secret(
        gateway.dh_private,
        node.dh_public
    )

    node_Z = derive_shared_secret(
        node.dh_private,
        gateway.dh_public
    )

    # Both parties must get the same Z
    if gateway_Z != node_Z:
        raise ValueError(
            "Gateway and Node derived different DH secrets"
        )

    print("DH shared secret matches.")


    #derive Gateway session keys
    gateway_keys = derive_session_keys(
        gateway_Z,
        TH
    )


    #derive Node session keys
    node_keys = derive_session_keys(
        node_Z,
        TH
    )

    # Verify all derived values match
    if gateway_keys != node_keys:
        raise ValueError(
            "Gateway and Node derived different session keys"
        )

    (
        K_master,
        K_g2n_enc,
        K_g2n_mac,
        K_n2g_enc,
        K_n2g_mac,
        session_id
    ) = gateway_keys

    print("Session keys match.")
    print("Session ID:", session_id.hex())

    print("\n--- Handshake successful ---")

    return {
        "transcript": transcript,
        "TH": TH,
        "K_master": K_master,
        "K_g2n_enc": K_g2n_enc,
        "K_g2n_mac": K_g2n_mac,
        "K_n2g_enc": K_n2g_enc,
        "K_n2g_mac": K_n2g_mac,
        "session_id": session_id,
    }



# Program
gateway = Party("gateway")
node = Party("node")

parameters = load_dh_parameters(
    "ffdhe3072.pem"
)

numbers = parameters.parameter_numbers()

print("DH prime size:", numbers.p.bit_length(), "bits")
print("DH generator:", numbers.g)

session = run_handshake(
    gateway,
    node,
    parameters
)

print("\nDerived values:")
print("K_master:", session["K_master"].hex())
print("K_g2n_enc:", session["K_g2n_enc"].hex())
print("K_g2n_mac:", session["K_g2n_mac"].hex())
print("K_n2g_enc:", session["K_n2g_enc"].hex())
print("K_n2g_mac:", session["K_n2g_mac"].hex())
print("session_id:", session["session_id"].hex())
