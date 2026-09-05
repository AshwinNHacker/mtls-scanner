# Example servers

Two minimal, self-contained TLS servers used to demonstrate (and integration-test) the
scanner. Both generate their own certificates on startup — nothing to configure, nothing
written outside the OS temp directory. **Neither is meant to be deployed anywhere real.**

## `vulnerable_server.py`

Requests a client certificate (mTLS looks "on" from the outside) but its verification
callback unconditionally returns success regardless of what OpenSSL's chain validation
actually concluded:

```python
def _broken_verify_callback(conn, cert, errnum, errdepth, ok):
    if not ok:
        print(f"cert verification FAILED (errnum={errnum}) - accepting anyway (BUG)")
    return True  # <-- should be `return ok`
```

This specific shape — log the failure, then let the connection through anyway — is a real
pattern, not a strawman; it shows up in debug code that ships to production, in
"just get it working" verify callbacks, and in Node's `rejectUnauthorized: false` paired with
manual (and incomplete) verification logic elsewhere in the request handler.

Python's stdlib `ssl` module can't reproduce this faithfully — once you ask it to verify a
peer certificate, it always performs full chain validation with no override hook — so this
example uses [pyOpenSSL](https://www.pyopenssl.org/), which exposes the same
`SSL_CTX_set_verify()` callback shape that real vulnerable code is built on.

```bash
pip install -e ".[dev]"   # installs pyOpenSSL
python examples/vulnerable_server.py --port 8443
```

## `secure_server.py`

Requires a client certificate (`ssl.CERT_REQUIRED`) and validates it against a CA the server
generates for itself on startup (`ssl.SSLContext.load_verify_locations`). Standard library
`ssl` is sufficient here because the stdlib's *correct* validation path is exactly what we
want to demonstrate against.

```bash
python examples/secure_server.py --port 8444
```

## Running the comparison

```bash
# terminal 1
python examples/vulnerable_server.py --port 8443

# terminal 2
python examples/secure_server.py --port 8444

# terminal 3
mtls-scanner localhost:8443   # -> VULNERABLE (self-signed, untrusted-CA, expired, ... all accepted)
mtls-scanner localhost:8444   # -> NO MISCONFIGURATIONS DETECTED
```

`tests/test_scanner_integration.py` runs exactly this comparison automatically as part of the
test suite, launching both servers as subprocesses on ephemeral ports.
