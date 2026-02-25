# Lethe relay server — runs on the VPS, accepts encrypted tunnel connections,
# negotiates session keys via X25519, decrypts Lethe packets to recover
# the real destination, and forwards traffic there on the client's behalf.


import asyncio
import ssl
import sys
sys.path.append('/root/lethe')
from shared.protocol import decrypt_packet, encrypt_packet, read_packet, generate_keypair, get_public_bytes, compute_shared_secret

async def pipe_encrypted(reader, writer, key, destination):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            encrypted = encrypt_packet(destination, data, key)
            writer.write(encrypted)
            await writer.drain()
    except Exception as e:
        print(f"pipe_encrypted error: {e}")

async def pipe_decrypted(reader, writer, key):
    try:
        while True:
            packet = await read_packet(reader)
            if not packet:
                break
            destination, data = decrypt_packet(packet, key)
            writer.write(data)
            await writer.drain()
    except Exception as e:
        print(f"pipe_decrypted error: {e}")

async def handle_client(reader, writer):
    dest_reader, dest_writer = None, None
    try:

        client_public_bytes = await reader.readexactly(32)
        

        private_key, public_key = generate_keypair()
        our_public_bytes = get_public_bytes(public_key)
        writer.write(our_public_bytes)
        await writer.drain()
        

        shared_secret = compute_shared_secret(private_key, client_public_bytes)
        print(f"Key exchange complete: {shared_secret.hex()[:16]}...")

        packet = await read_packet(reader)
        destination, data = decrypt_packet(packet, shared_secret)
        print(f"Destination: {destination}, first chunk: {len(data)} bytes")

        host, port = destination.rsplit(':', 1)
        port = int(port)

        dest_reader, dest_writer = await asyncio.open_connection(host, port)
        print(f"Connected to {host}:{port}")

        dest_writer.write(data)
        await dest_writer.drain()

        await asyncio.gather(
            pipe_encrypted(dest_reader, writer, shared_secret, destination),
            pipe_decrypted(reader, dest_writer, shared_secret),
            return_exceptions=True
        )

    except Exception as e:
        print(f"Error: {e}")
    finally:
        writer.close()
        if dest_writer:
            dest_writer.close()

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        # your domain certificates
    )
    
    server = await asyncio.start_server(
        handle_client,
        '0.0.0.0',
        443,
        ssl=ctx
    )
    print("Lethe relay listening on 0.0.0.0:443 with TLS")
    async with server:
        await server.serve_forever()

asyncio.run(main())