# Lethe tunnel client — performs X25519 key exchange with the VPS relay,
# wraps all traffic in ChaCha20-Poly1305 encryption inside a TLS 1.3
# connection so the tunnel looks like normal HTTPS to an observer.


import sys
sys.path.append('.')
import asyncio
import ssl
from shared.protocol import encrypt_packet, decrypt_packet, read_packet, generate_keypair, get_public_bytes, compute_shared_secret
from config import VPS_IP, VPS_PORT, VPS_DOMAIN

class TunnelConnection:
    def __init__(self, reader, writer, key, destination):
        self.reader = reader
        self.writer = writer
        self.key = key
        self.destination = destination

    async def read(self, n):
        try:
            encrypted = await read_packet(self.reader)
            if not encrypted:
                return b''
            destination, data = decrypt_packet(encrypted, self.key)
            return data
        except Exception as e:
            print(f"tunnel.read error: {e}")
            return b''

    async def write(self, data):
        encrypted = encrypt_packet(self.destination, data, self.key)
        self.writer.write(encrypted)

    async def drain(self):
        await self.writer.drain()

    def close(self):
        self.writer.close()

async def open_tunnel(host, port):
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.open_connection(
        VPS_IP, VPS_PORT,
        ssl=ctx,
        server_hostname=VPS_DOMAIN
    )
    
    private_key, public_key = generate_keypair()
    our_public_bytes = get_public_bytes(public_key)
    
    writer.write(our_public_bytes)
    await writer.drain()
    
    vps_public_bytes = await reader.readexactly(32)
    shared_secret = compute_shared_secret(private_key, vps_public_bytes)
    print(f"Key exchange complete: {shared_secret.hex()[:16]}...")
    
    destination = f"{host}:{port}"
    return TunnelConnection(reader, writer, shared_secret, destination)