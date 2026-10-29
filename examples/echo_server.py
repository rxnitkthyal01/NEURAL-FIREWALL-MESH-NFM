"""One-request TCP echo service for the local NFM walkthrough."""

from __future__ import annotations

import argparse
import asyncio


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    data = await reader.readline()
    writer.write(data)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def main(host: str, port: int) -> None:
    server = await asyncio.start_server(handle, host, port)
    print(f"one-request echo listening on {host}:{port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9001)
    args = parser.parse_args()
    asyncio.run(main(args.host, args.port))
