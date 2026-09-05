#!/usr/bin/env python3
"""
Intentionally VULNERABLE example mTLS server.

This models a very common real-world bug: the server requests a client
certificate (mTLS is "on") but its verification callback always returns
success regardless of what OpenSSL's chain validation actually concluded -
e.g. a hand-rolled `verify_callback` that returns `True` unconditionally
("just log it and let it through"), Node's `rejectUnauthorized: false`
paired with manual (and broken) verification, or a Java TrustManager whose
`checkClientTrusted()` is a no-op. Python's stdlib `ssl` module doesn't
expose a hook that can reproduce this faithfully (it always performs full
chain validation once verification is requested), so this example uses
pyOpenSSL, whose `set_verify()` callback maps directly onto the pattern
seen in real vulnerable code.

Do not deploy this configuration anywhere real - it exists purely to give
mtls-scanner something to demonstrate against.

Usage:
    python examples/vulnerable_server.py [--port 8443]

Then, in another terminal:
    mtls-scanner localhost:8443
"""

from __future__ import annotations

import argparse
import datetime
import socket
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import SSL


def _make_server_cert() -> tuple:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tempfile.mktemp(suffix=".crt.pem")
    key_path = tempfile.mktemp(suffix=".key.pem")
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(key_path).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _broken_verify_callback(conn, cert, errnum, errdepth, ok):
    """
    THE BUG.

    A real chain-validation failure is reported to this callback via `ok`
    (0 = invalid) and `errnum` (the X509 error code - expired, self-signed,
    unknown issuer, etc). A correct callback returns that verdict. This one
    logs the (possibly damning) verdict and then unconditionally returns
    True, so every client certificate is accepted no matter what OpenSSL
    concluded about it. This exact shape - "log the error, return true
    anyway" - shows up repeatedly in real incident writeups.
    """
    subject = cert.get_subject()
    if not ok:
        print(f"[vulnerable-server] cert verification FAILED (errnum={errnum}) for "
              f"CN={subject.CN!r} - accepting anyway (BUG)")
    return True  # <-- should be `return ok`


def handle(conn) -> None:
    try:
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    except (SSL.Error, OSError):
        pass
    finally:
        try:
            conn.shutdown()
        except SSL.Error:
            pass
        conn.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()

    cert_path, key_path = _make_server_cert()

    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.use_certificate_file(cert_path)
    ctx.use_privatekey_file(key_path)

    # Requests a client cert (mTLS is "on")...
    ctx.set_verify(SSL.VERIFY_PEER, _broken_verify_callback)
    # ...but because the callback above always returns True, this is
    # equivalent to not validating the chain at all. No CA bundle is even
    # loaded, which is itself a second, related smell.

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(20)

    print(f"[vulnerable-server] listening on {args.host}:{args.port} (mTLS requested, verify callback broken)")
    print("[vulnerable-server] Ctrl+C to stop")

    try:
        while True:
            raw, addr = sock.accept()
            tls_conn = SSL.Connection(ctx, raw)
            tls_conn.set_accept_state()
            try:
                tls_conn.do_handshake()
            except SSL.Error as exc:
                print(f"[vulnerable-server] handshake failed from {addr}: {exc}")
                raw.close()
                continue
            threading.Thread(target=handle, args=(tls_conn,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
