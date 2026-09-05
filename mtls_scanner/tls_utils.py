"""
Low-level TLS handshake helpers.

These functions perform *raw* handshakes against a target host:port,
optionally presenting a client certificate, and report back whether the
handshake succeeded. The scanner never verifies the target's own server
certificate here (that's a separate, orthogonal concern) - the goal is
strictly to observe how the target validates the *client* certificate it
receives, which is the essence of an mTLS trust-chain check.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass
from typing import Optional


DEFAULT_TIMEOUT = 8.0


@dataclass
class HandshakeOutcome:
    success: bool
    error: Optional[str] = None
    error_type: Optional[str] = None
    negotiated_protocol: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    peer_cert_present: bool = False


def _base_context(
    min_version: Optional[ssl.TLSVersion] = None,
    max_version: Optional[ssl.TLSVersion] = None,
    allow_weak_local_key: bool = False,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # We are not evaluating the *server's* certificate here - only how the
    # server treats the client certificate we present. Disabling hostname
    # checking / server-cert verification keeps this check isolated.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        # TLSv1 / TLSv1.1 are intentionally probed by the legacy-protocol
        # check even though the ssl module deprecates the constants used to
        # request them; the deprecation is expected and not actionable here.
        warnings.simplefilter("ignore", DeprecationWarning)
        if min_version is not None:
            ctx.minimum_version = min_version
        if max_version is not None:
            ctx.maximum_version = max_version
    if allow_weak_local_key:
        # OpenSSL's default security level (usually 2) refuses to even
        # *load* a sub-2048-bit RSA key locally, independent of anything
        # the network peer does. The weak-key check needs to load such a
        # key on purpose, so its security level is relaxed just for this
        # one context - this has no effect on what the remote server does
        # or accepts.
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return ctx


def attempt_handshake(
    host: str,
    port: int,
    *,
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    min_version: Optional[ssl.TLSVersion] = None,
    max_version: Optional[ssl.TLSVersion] = None,
    allow_weak_local_key: bool = False,
) -> HandshakeOutcome:
    """
    Attempt a TLS handshake against host:port, optionally presenting a
    client certificate. Returns a HandshakeOutcome describing what
    happened. A handshake that *completes* means the server accepted
    whatever client certificate (or lack thereof) was presented.
    """
    ctx = _base_context(min_version, max_version, allow_weak_local_key=allow_weak_local_key)

    if cert_path and key_path:
        try:
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        except ssl.SSLError as exc:
            return HandshakeOutcome(
                success=False,
                error=f"Failed to load local test certificate: {exc}",
                error_type="local_cert_error",
            )

    raw_sock = None
    tls_sock = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        cipher = tls_sock.cipher()
        protocol = tls_sock.version()

        # IMPORTANT (TLS 1.3 subtlety): in TLS 1.3, client authentication is
        # validated by the server *after* it has already sent its own
        # Finished message. A client-side call to wrap_socket() can return
        # successfully even when the server is about to reject the
        # connection - the rejection alert (bad_certificate,
        # unknown_ca, certificate_required, ...) may only arrive once the
        # client attempts to read or write on the connection. Treating a
        # completed client-side handshake alone as "accepted" would produce
        # false positives against correctly configured TLS 1.3 servers, so
        # we perform a small post-handshake liveness probe to get a
        # trustworthy verdict on both TLS 1.2 and TLS 1.3.
        confirmed = _confirm_post_handshake(tls_sock)
        if not confirmed.ok:
            return HandshakeOutcome(
                success=False,
                error=confirmed.error,
                error_type="ssl_error",
                negotiated_protocol=protocol,
                negotiated_cipher=cipher[0] if cipher else None,
            )

        return HandshakeOutcome(
            success=True,
            negotiated_protocol=protocol,
            negotiated_cipher=cipher[0] if cipher else None,
            peer_cert_present=tls_sock.getpeercert(binary_form=True) is not None,
        )
    except ssl.SSLError as exc:
        return HandshakeOutcome(success=False, error=str(exc), error_type="ssl_error")
    except socket.timeout:
        return HandshakeOutcome(success=False, error="Connection timed out", error_type="timeout")
    except ConnectionRefusedError:
        return HandshakeOutcome(success=False, error="Connection refused", error_type="refused")
    except OSError as exc:
        return HandshakeOutcome(success=False, error=str(exc), error_type="os_error")
    finally:
        for s in (tls_sock, raw_sock):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass


@dataclass
class _ProbeResult:
    ok: bool
    error: Optional[str] = None


def _confirm_post_handshake(tls_sock: ssl.SSLSocket, probe_timeout: float = 1.5) -> _ProbeResult:
    """
    After a client-side handshake reports completion, perform a minimal
    read/write exchange to detect a delayed rejection (most notably TLS 1.3
    post-handshake certificate rejection alerts, but this also has the nice
    side effect of confirming TLS 1.2 renegotiation-based client-auth
    rejections). A harmless single CRLF is written - enough to make most
    request/response protocols (including our bundled example servers)
    respond, without being interpreted as a meaningful request.
    """
    original_timeout = tls_sock.gettimeout()
    try:
        tls_sock.settimeout(probe_timeout)

        # First, a non-blocking-ish peek: some servers send the rejection
        # alert immediately without waiting for client data.
        try:
            data = tls_sock.recv(1)
            if data == b"":
                return _ProbeResult(ok=False, error="Connection closed by peer immediately after handshake (EOF)")
            # Got real application data unprompted - definitely accepted.
            return _ProbeResult(ok=True)
        except ssl.SSLWantReadError:
            pass
        except socket.timeout:
            pass  # no immediate alert; continue to the write probe
        except ssl.SSLError as exc:
            return _ProbeResult(ok=False, error=f"Server rejected connection post-handshake: {exc}")
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            return _ProbeResult(ok=False, error=f"Connection reset post-handshake: {exc}")

        # Nothing arrived unprompted - nudge the server with a harmless probe.
        try:
            tls_sock.sendall(b"\r\n")
        except ssl.SSLError as exc:
            return _ProbeResult(ok=False, error=f"Server rejected connection when writing: {exc}")
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            return _ProbeResult(ok=False, error=f"Connection reset when writing: {exc}")

        try:
            tls_sock.recv(1)
            # Either data or a clean (non-erroring) read - connection is alive.
            return _ProbeResult(ok=True)
        except socket.timeout:
            # No response, but also no rejection alert - most likely the
            # server is simply waiting for a well-formed request. Since no
            # TLS-level rejection occurred, treat the certificate as accepted.
            return _ProbeResult(ok=True)
        except ssl.SSLError as exc:
            return _ProbeResult(ok=False, error=f"Server rejected connection post-handshake: {exc}")
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            return _ProbeResult(ok=False, error=f"Connection reset post-handshake: {exc}")
    finally:
        try:
            tls_sock.settimeout(original_timeout)
        except OSError:
            pass


def check_port_open(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_tls_version(host: str, port: int, version: ssl.TLSVersion, timeout: float = DEFAULT_TIMEOUT) -> HandshakeOutcome:
    """Check whether the server will negotiate a specific TLS version at all
    (independent of client certificates)."""
    return attempt_handshake(host, port, timeout=timeout, min_version=version, max_version=version)
