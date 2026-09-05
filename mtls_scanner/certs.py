"""
Dynamic X.509 certificate generation.

The scanner needs to present several *deliberately imperfect* client
certificates to a target mTLS endpoint in order to test whether the server
validates the certificate chain correctly. Everything here is generated
in-memory (nothing is written to disk unless explicitly requested) using
the `cryptography` library.
"""

from __future__ import annotations

import datetime
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


@dataclass
class GeneratedCert:
    """An in-memory certificate + private key pair, plus PEM temp files."""

    cert: x509.Certificate
    key: rsa.RSAPrivateKey
    cert_path: str
    key_path: str
    label: str

    def cleanup(self) -> None:
        for p in (self.cert_path, self.key_path):
            try:
                Path(p).unlink(missing_ok=True)
            except OSError:
                pass


def _new_key(size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write_pem_pair(cert: x509.Certificate, key: rsa.RSAPrivateKey, label: str) -> Tuple[str, str]:
    """Write a cert/key pair to temp files and return their paths."""
    cert_fd, cert_path = tempfile.mkstemp(prefix=f"mtls_{label}_", suffix=".crt.pem")
    key_fd, key_path = tempfile.mkstemp(prefix=f"mtls_{label}_", suffix=".key.pem")

    with open(cert_fd, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_fd, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return cert_path, key_path


def make_ca(cn: str = "mtls-scanner Test Root CA") -> GeneratedCert:
    """Create a throwaway self-signed CA (used to sign the 'wrong CA' leaf)."""
    key = _new_key()
    subject = issuer = _name(cn)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = _write_pem_pair(cert, key, "ca")
    return GeneratedCert(cert=cert, key=key, cert_path=cert_path, key_path=key_path, label="untrusted-ca")


def make_leaf(
    *,
    label: str,
    cn: str = "mtls-scanner-client",
    signer_key: Optional[rsa.RSAPrivateKey] = None,
    signer_subject: Optional[x509.Name] = None,
    not_before_delta: datetime.timedelta = datetime.timedelta(days=-1),
    not_after_delta: datetime.timedelta = datetime.timedelta(days=365),
    self_signed: bool = False,
    include_client_auth_eku: bool = True,
    key_size: int = 2048,
) -> GeneratedCert:
    """
    Build a leaf certificate with configurable defects.

    - self_signed=True                -> issuer == subject, signed by its own key
    - signer_key/signer_subject given  -> signed by an unrelated ("untrusted") CA
    - not_before_delta/not_after_delta -> control expiry / not-yet-valid windows
    - include_client_auth_eku=False    -> omit the clientAuth Extended Key Usage
    """
    key = _new_key(key_size)
    subject = _name(cn)
    now = datetime.datetime.now(datetime.timezone.utc)

    if self_signed:
        issuer = subject
        signing_key = key
    elif signer_key is not None and signer_subject is not None:
        issuer = signer_subject
        signing_key = signer_key
    else:
        raise ValueError("Must specify self_signed=True or provide signer_key/signer_subject")

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + not_before_delta)
        .not_valid_after(now + not_after_delta)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mtls-scanner.invalid")]),
            critical=False,
        )
    )

    if include_client_auth_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    else:
        # Deliberately wrong EKU: serverAuth only, no clientAuth
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )

    cert = builder.sign(signing_key, hashes.SHA256())
    cert_path, key_path = _write_pem_pair(cert, key, label)
    return GeneratedCert(cert=cert, key=key, cert_path=cert_path, key_path=key_path, label=label)


class CertificateTestSet:
    """
    Generates and caches the full family of test certificates used by the
    scan checks. Created once per scan and cleaned up afterwards.
    """

    def __init__(self) -> None:
        self._generated: list = []
        self._untrusted_ca: Optional[GeneratedCert] = None

    @property
    def untrusted_ca(self) -> GeneratedCert:
        if self._untrusted_ca is None:
            self._untrusted_ca = make_ca()
            self._generated.append(self._untrusted_ca)
        return self._untrusted_ca

    def _track(self, gc: GeneratedCert) -> GeneratedCert:
        self._generated.append(gc)
        return gc

    def self_signed_valid(self) -> GeneratedCert:
        return self._track(make_leaf(label="self-signed", self_signed=True))

    def signed_by_untrusted_ca(self) -> GeneratedCert:
        ca = self.untrusted_ca
        return self._track(
            make_leaf(
                label="untrusted-ca-signed",
                signer_key=ca.key,
                signer_subject=ca.cert.subject,
            )
        )

    def expired(self) -> GeneratedCert:
        ca = self.untrusted_ca
        return self._track(
            make_leaf(
                label="expired",
                signer_key=ca.key,
                signer_subject=ca.cert.subject,
                not_before_delta=datetime.timedelta(days=-400),
                not_after_delta=datetime.timedelta(days=-30),
            )
        )

    def not_yet_valid(self) -> GeneratedCert:
        ca = self.untrusted_ca
        return self._track(
            make_leaf(
                label="not-yet-valid",
                signer_key=ca.key,
                signer_subject=ca.cert.subject,
                not_before_delta=datetime.timedelta(days=30),
                not_after_delta=datetime.timedelta(days=395),
            )
        )

    def wrong_eku(self) -> GeneratedCert:
        ca = self.untrusted_ca
        return self._track(
            make_leaf(
                label="wrong-eku",
                signer_key=ca.key,
                signer_subject=ca.cert.subject,
                include_client_auth_eku=False,
            )
        )

    def weak_key(self) -> GeneratedCert:
        ca = self.untrusted_ca
        return self._track(
            make_leaf(
                label="weak-key-1024",
                signer_key=ca.key,
                signer_subject=ca.cert.subject,
                key_size=1024,
            )
        )

    def cleanup(self) -> None:
        for gc in self._generated:
            gc.cleanup()
        self._generated.clear()
