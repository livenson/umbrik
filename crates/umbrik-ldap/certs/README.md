# Bundled certificates

## `digicert-global-g2-tls-rsa-sha256-2020-ca1.der`

The intermediate CA that issued `esteid.ldap.sk.ee`'s TLS certificate. SK's directory does not
send it during the handshake, so clients that do not fetch missing intermediates themselves
(rustls, which umbrik uses; OpenSSL) cannot build a chain to a trusted root. See
`SK_INTERMEDIATE_DER` and `CompletingVerifier` in `src/lib.rs`.

| | |
|---|---|
| Subject | `C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1` |
| Issuer | `C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2` |
| Valid | 2021-03-30 to 2031-03-29 |
| Subject Key Identifier | `74:85:80:C0:66:C7:DF:37:DE:CF:BD:29:37:AA:03:1D:BE:ED:CD:17` |
| SHA-256 | `c8025f9fc65fdfc95b3ca8cc7867b9a587b5277973957917463fc813d0b625a9` |
| Source | `http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt` |

The source is the CA Issuers URL in the server certificate's Authority Information Access
extension. Its Subject Key Identifier matches that certificate's Authority Key Identifier, and it
verifies against DigiCert Global Root G2 from the system trust store. It is appended to the
intermediates the server sends, never added as a trust anchor: the chain must still end at a root
in the system store, so it grants no new trust. The tests in `src/lib.rs` check both properties.

Check the file:

```bash
shasum -a 256 crates/umbrik-ldap/certs/digicert-global-g2-tls-rsa-sha256-2020-ca1.der
```

Check whether SK still omits it (one certificate listed means yes):

```bash
echo | openssl s_client -connect esteid.ldap.sk.ee:636 -servername esteid.ldap.sk.ee -showcerts \
  2>/dev/null | grep -c 'BEGIN CERTIFICATE'
```

**Remove** the file and `SK_INTERMEDIATE_DER` once SK serves the full chain. **Replace** them if
SK's server certificate is reissued under a different intermediate. Every SK lookup will then
fail with `UnknownIssuer` again until this is updated.
