# Check Reference

Detailed notes on every check the scanner performs: what it does, why the property matters,
what a `VULNERABLE` verdict proves, and how to fix it. Check IDs match the `check_id` field in
JSON output and the `--checks` CLI flag (which takes method names, e.g.
`check_self_signed_accepted`).

---

## `baseline-no-cert` — Client certificate requirement

**What it does:** Attempts a TLS handshake presenting no client certificate at all.

**Why it matters:** This is context, not a vulnerability check. A server that completes the
handshake without any client certificate simply doesn't enforce mTLS on this port/path — which
may be entirely intentional (client certs optional, or enforced at the application layer, or
enforced on a different port). The other checks are only meaningful in relation to this
baseline: if mTLS isn't enforced at all, "the server accepted an invalid certificate" is a much
smaller finding than it would be on an endpoint that's supposed to be locked down.

**Severity:** INFO (always).

---

## `self-signed-cert` — Self-signed client certificate acceptance

**What it does:** Presents a freshly generated, self-signed leaf certificate (`issuer ==
subject`) with an otherwise normal validity window and Extended Key Usage.

**Why it matters:** This is the most basic X.509 path validation failure possible — there is
no chain to validate because the certificate's only "issuer" is itself. Any TLS stack
performing real chain validation against a configured trust anchor will reject this
immediately with `unknown_ca` or `self signed certificate`.

**If VULNERABLE:** The server is not building/validating a certificate chain at all. This is
functionally equivalent to having no client authentication — any party can generate a keypair
and a self-signed certificate in seconds and authenticate.

**Severity:** CRITICAL.

**Common root causes:**
- nginx: `ssl_verify_client optional_no_ca` instead of `on` / `optional` with a configured
  `ssl_client_certificate`.
- A custom TLS verify callback (Node `tls.createServer({ requestCert: true })` without
  checking `req.client.authorized`; a Java `X509TrustManager.checkClientTrusted()` that is a
  no-op or always returns).
- HAProxy `verify none` combined with `ca-file` — `verify` controls enforcement independently
  of whether a CA file is configured.

**Fix:** Configure the TLS terminator to validate the full client certificate chain against a
pinned, trusted CA bundle dedicated to client authentication, and reject any certificate that
does not chain to it.

---

## `untrusted-ca-cert` — Untrusted CA-signed certificate acceptance

**What it does:** Presents a leaf certificate that is validly signed — but by a throwaway CA
generated fresh by the scanner for this run, which the target has never been configured to
trust.

**Why it matters:** Unlike the self-signed check, this certificate has a perfectly normal
chain — it's just a chain to the wrong root. A server correctly performing path validation
against its own trust anchors will reject it just as readily as a self-signed cert; a server
that only checks "is this signature internally consistent" (without checking *whose* CA it is)
will accept it.

**If VULNERABLE:** Strongly suggests the server is validating against an overly broad trust
store — most commonly the OS/language runtime's default public CA bundle — rather than a
dedicated client-CA bundle. In that scenario, *any* certificate issued by *any* public CA
(e.g., a Let's Encrypt certificate for an unrelated domain, purchased/obtained by an attacker
in minutes) can authenticate as a client.

**Severity:** CRITICAL.

**Fix:** Validate client certificates against an explicit, pinned CA bundle used only for
client authentication — never the system default trust store.

---

## `expired-cert` — Expired certificate acceptance

**What it does:** Presents a certificate, signed by the scanner's throwaway CA, whose
`notAfter` is 30 days in the past (and `notBefore` further back still, so the entire validity
window is in the past).

**Why it matters:** `notBefore`/`notAfter` checking is one of the most basic, mandatory steps
of X.509 path validation (RFC 5280 §6.1.3). Skipping it means a certificate remains usable
forever, regardless of the issuer's intent — including certificates that were only ever meant
to be short-lived (e.g. rotated automatically every 90 days) but whose revocation/rotation
tooling silently stopped working.

**If VULNERABLE:** Credentials do not actually expire from the server's point of view.
Combined with no revocation checking (which this tool cannot test black-box — see
[ARCHITECTURE.md](ARCHITECTURE.md#explicit-non-goals)), this means there may be no way to
un-authorize a compromised or decommissioned client short of changing the trusted CA itself.

**Severity:** HIGH.

**Fix:** Confirm the TLS stack performs full path validation including date checks, not just
signature verification. Some libraries expose "verify signature only" modes for testing that
occasionally leak into production configuration.

---

## `not-yet-valid-cert` — Not-yet-valid certificate acceptance

**What it does:** Presents a certificate whose `notBefore` is 30 days in the future.

**Why it matters:** The mirror image of the expiry check — confirms date-range validation is
enforced on both ends of the window, not just the "has it expired" direction. A server that
only checks `notAfter` (a surprisingly common shortcut, since "is this cert expired" is the
more commonly discussed check) will still accept this certificate.

**If VULNERABLE:** Further evidence that date-range validation isn't implemented at all,
usually alongside a VULNERABLE `expired-cert` result.

**Severity:** MEDIUM (lower than expired, since not-yet-valid certificates are less likely to
be actively circulating as compromised credentials — but it confirms the same underlying gap).

**Fix:** Same as `expired-cert`.

---

## `wrong-eku-cert` — Incorrect Extended Key Usage acceptance

**What it does:** Presents a certificate, otherwise fully valid and correctly chained to the
scanner's throwaway CA, whose Extended Key Usage extension declares only `serverAuth` (OID
`1.3.6.1.5.5.7.3.1`) — omitting `clientAuth` (OID `1.3.6.1.5.5.7.3.2`) entirely.

**Why it matters:** Extended Key Usage is how a CA scopes what a certificate is *for*.
Enforcing it prevents a certificate minted for one purpose (e.g. a TLS server certificate for
an internal service, or a code-signing cert) from being repurposed for client authentication,
even if it happens to chain to a trust anchor the mTLS server does recognize — which is common
in organizations that operate one internal PKI for everything.

**If VULNERABLE:** The mTLS deployment does not scope which certificates from its trusted CA(s)
are actually authorized for client authentication. In shared-PKI environments this can allow
certificates issued for unrelated systems to authenticate.

**Severity:** MEDIUM.

**Fix:** Enforce Extended Key Usage checks so only certificates explicitly issued with
`clientAuth` are accepted. Most TLS libraries expose this as a configuration flag (e.g. OpenSSL
`X509_PURPOSE_SSL_CLIENT`) separate from basic chain validation, and it's easy to miss.

---

## `weak-key-cert` — Weak key size acceptance

**What it does:** Presents a certificate, correctly chained to the scanner's throwaway CA,
built on a 1024-bit RSA key rather than 2048+.

**Why it matters:** 1024-bit RSA is considered cryptographically weak by current standards
(NIST SP 800-131A and the CA/Browser Forum Baseline Requirements both call for a 2048-bit
minimum). A server accepting such a key isn't enforcing a minimum key-strength policy during
certificate validation.

**Note:** Because this leaf is signed by the same throwaway CA as the `untrusted-ca-cert`
check, a target that already fails that check will also "pass" (be accepted) here for the same
underlying reason — the weak key size is a secondary property being probed, layered on the
same untrusted-CA scenario deliberately, so this check is only cleanly informative on servers
that already correctly reject untrusted CAs.

**Severity:** LOW.

**Fix:** Enforce a minimum key size policy (RSA ≥ 2048 bits, or EC P-256/P-384) as part of
client certificate validation, in addition to full chain validation.

**Known limitation:** Some OpenSSL builds refuse to even *load* a 1024-bit key locally under
their default security level; the scanner lowers `SECLEVEL` for its own local context only when
running this specific check (see `tls_utils._base_context(allow_weak_local_key=True)`) — this
has no effect on the network peer.

---

## `legacy-tls-versions` — Legacy TLS protocol support

**What it does:** Independent of client certificates, attempts to negotiate TLS 1.0 and TLS
1.1 specifically against the target.

**Why it matters:** Not a client-certificate-chain check, but closely related mTLS hardening
signal: legacy protocol versions lack modern AEAD-only cipher suite guarantees and downgrade
resistance, widening the attack surface available to intercept or downgrade a
client-authenticated session. TLS 1.0/1.1 are disallowed by PCI-DSS and most modern compliance
frameworks.

**Severity:** LOW.

**Fix:** Disable TLS 1.0 and TLS 1.1; require TLS 1.2 as a minimum, and prefer TLS 1.3.

---

## Interpreting `INCONCLUSIVE` results

An `INCONCLUSIVE` verdict means the scanner could not attribute a definite outcome to
certificate validation — usually a network-level issue (timeout, connection reset, or a local
certificate-loading failure). It is not evidence of either secure or vulnerable behavior;
re-run the scan, and if it persists, check network reachability and firewall rules between the
scanner and the target.
