import datetime
import os

import pytest

from mtls_scanner.certs import CertificateTestSet, make_ca, make_leaf


def test_make_ca_is_self_signed_and_is_ca():
    ca = make_ca()
    assert ca.cert.subject == ca.cert.issuer
    bc = ca.cert.extensions.get_extension_for_class(__import__("cryptography.x509", fromlist=["BasicConstraints"]).BasicConstraints)
    assert bc.value.ca is True
    ca.cleanup()


def test_make_leaf_self_signed():
    leaf = make_leaf(label="test", self_signed=True)
    assert leaf.cert.subject == leaf.cert.issuer
    assert os.path.exists(leaf.cert_path)
    assert os.path.exists(leaf.key_path)
    leaf.cleanup()
    assert not os.path.exists(leaf.cert_path)
    assert not os.path.exists(leaf.key_path)


def test_make_leaf_requires_signer_or_self_signed():
    with pytest.raises(ValueError):
        make_leaf(label="bad")


def test_expired_leaf_is_actually_expired():
    ca = make_ca()
    leaf = make_leaf(
        label="expired",
        signer_key=ca.key,
        signer_subject=ca.cert.subject,
        not_before_delta=datetime.timedelta(days=-400),
        not_after_delta=datetime.timedelta(days=-30),
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    assert leaf.cert.not_valid_after_utc < now
    ca.cleanup()
    leaf.cleanup()


def test_not_yet_valid_leaf():
    ca = make_ca()
    leaf = make_leaf(
        label="nyv",
        signer_key=ca.key,
        signer_subject=ca.cert.subject,
        not_before_delta=datetime.timedelta(days=30),
        not_after_delta=datetime.timedelta(days=395),
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    assert leaf.cert.not_valid_before_utc > now
    ca.cleanup()
    leaf.cleanup()


def test_certificate_set_generates_all_variants_and_cleans_up():
    cs = CertificateTestSet()
    generated = [
        cs.self_signed_valid(),
        cs.signed_by_untrusted_ca(),
        cs.expired(),
        cs.not_yet_valid(),
        cs.wrong_eku(),
        cs.weak_key(),
    ]
    for gc in generated:
        assert os.path.exists(gc.cert_path)
        assert os.path.exists(gc.key_path)

    weak = generated[-1]
    assert weak.key.key_size == 1024

    paths = [gc.cert_path for gc in generated] + [gc.key_path for gc in generated]
    cs.cleanup()
    for p in paths:
        assert not os.path.exists(p)


def test_wrong_eku_omits_client_auth():
    from cryptography.x509.oid import ExtendedKeyUsageOID

    cs = CertificateTestSet()
    gc = cs.wrong_eku()
    eku = gc.cert.extensions.get_extension_for_class(__import__("cryptography.x509", fromlist=["ExtendedKeyUsage"]).ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value
    cs.cleanup()
