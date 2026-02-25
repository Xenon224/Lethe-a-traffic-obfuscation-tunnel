# Shared packet format and cryptography for the Lethe tunnel.
# Packet structure: [4B length][12B nonce][ciphertext]
# Plaintext structure: [2B dest_len][destination][payload]
# Both client and relay import this — any change must be updated on both sides.


from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption, PrivateFormat
import os

def encrypt_packet(destination, data, key):
    nonce = os.urandom(12)
    dest_bytes = destination.encode()
    dest_len = len(dest_bytes).to_bytes(2, 'big')
    plaintext = dest_len + dest_bytes + data
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    packet = nonce + ciphertext
    return len(packet).to_bytes(4, 'big') + packet

def decrypt_packet(packet, key):
    nonce = packet[:12]
    ciphertext = packet[12:]
    plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    dest_len = int.from_bytes(plaintext[:2], 'big')
    destination = plaintext[2:2+dest_len].decode()
    data = plaintext[2+dest_len:]
    return destination, data

async def read_packet(reader):
    length_bytes = await reader.readexactly(4)
    length = int.from_bytes(length_bytes, 'big')
    packet = await reader.readexactly(length)
    return packet

def generate_keypair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key , public_key

def compute_shared_secret(private_key, peer_public_key_bytes):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def get_public_bytes(public_key):
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)