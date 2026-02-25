# SOCKS5 proxy server — intercepts browser traffic at the socket level,
# extracts the destination from the SOCKS5 handshake, and routes it
# through the Lethe encrypted tunnel instead of connecting directly.


import asyncio
import sys
sys.path.append('.')
from client.tunnel import open_tunnel

from config import  VPS_IP, VPS_PORT, PROXY_HOST, PROXY_PORT

async def pipe_to_tunnel(reader, tunnel):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            await tunnel.write(data)
            await tunnel.drain()
    except Exception as e:
        print(f"pipe_to_tunnel error: {e}")

async def pipe_from_tunnel(tunnel, writer):
    try:
        while True:
            data = await tunnel.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception as e:
        print(f"pipe_from_tunnel error: {e}")

async def handle_greeting(reader, writer):
    data = await reader.read(1024)
    if data[0] != 0x05:
        writer.close()
        return False
    writer.write(b'\x05\x00')
    await writer.drain()
    return True

async def handle_request(reader, writer):
    data = await reader.read(1024)
    if data[1] != 0x01:
        writer.close()
        return None, None
    
    addr_type = data[3]
    
    if addr_type == 0x01:                          # parse IPv4
        host = '.'.join(str(b) for b in data[4:8])
        port = int.from_bytes(data[8:10], 'big')
    elif addr_type == 0x03:                        #domain
        domain_len = data[4]
        host = data[5:5+domain_len].decode()
        port = int.from_bytes(data[5+domain_len:7+domain_len], 'big')
    elif addr_type == 0x04:                        # IPV6
        host = ':'.join(f'{data[i]:02x}{data[i+1]:02x}'
                       for i in range(4, 20, 2))
        port = int.from_bytes(data[20:22], 'big')
    else:
        writer.close()
        return None, None

    writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00') # responed to browser
    await writer.drain()
    return host, port

async def handle_client(reader, writer):
    tunnel = None
    try:
        if not await handle_greeting(reader, writer):
            return
        host, port = await handle_request(reader, writer)
        if host is None:
            return
        print(f"Request to: {host}:{port}")
        tunnel = await open_tunnel(host, port)
        await asyncio.gather(                                 # Bi-Direction comminication
            pipe_to_tunnel(reader, tunnel),
            pipe_from_tunnel(tunnel, writer),
            return_exceptions=True
        )
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        writer.close()
        if tunnel:
            tunnel.close()

async def main():
    server = await asyncio.start_server(
        handle_client,
        '127.0.0.1',
        1080
    )
    print("SOCKS5 proxy listening on 127.0.0.1:1080")
    async with server:
        await server.serve_forever()

asyncio.run(main())