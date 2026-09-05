#!/usr/bin/env python3
"""
Example CORRECTLY configured mTLS server.

Requires client certificates and validates them against a pinned CA that
the server itself generates on startup (`server_ca.pem`, printed to
stdout). Contrast this with vulnerable_server.py - mtls-scanner should
report this server as SECURE across all checks.

Usage:
    python examples/secure_server.py [--port 8444]

Then, in another terminal:
    mtls-scanner localhost:8444
"""

from __future__ import annotations

import argparse
import datetime
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _make_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example Secure Server Client CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _make_server_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _write(cert, key, prefix):
    cert_path = tempfile.mktemp(prefix=prefix, suffix=".crt.pem")
    key_path = tempfile.mktemp(prefix=prefix, suffix=".key.pem")
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(key_path).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def handle(conn: ssl.SSLSocket) -> None:
    try:
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    except OSError:
        pass
    finally:
        conn.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8444)
    args = ap.parse_args()

    ca_cert, ca_key = _make_ca()
    ca_path, _ = _write(ca_cert, ca_key, "example_ca_")

    server_cert, server_key = _make_server_cert()
    server_cert_path, server_key_path = _write(server_cert, server_key, "example_server_")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(server_cert_path, server_key_path)

    # THE FIX: require a client cert AND validate it against a pinned CA bundle.
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(20)

    print(f"[secure-server] listening on {args.host}:{args.port} (mTLS required + validated)")
    print(f"[secure-server] trusted client CA written to: {ca_path}")
    print("[secure-server] Ctrl+C to stop")

    try:
        while True:
            raw, addr = sock.accept()
            try:
                tls_conn = ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError as exc:
                print(f"[secure-server] handshake correctly rejected {addr}: {exc}")
                raw.close()
                continue
            threading.Thread(target=handle, args=(tls_conn,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
