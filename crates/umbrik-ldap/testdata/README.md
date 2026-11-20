# Test fixtures

Public certificates for the offline chain-verification tests in `src/lib.rs`. None of them is
used at run time.

| File | Certificate | SHA-256 of the DER |
|---|---|---|
| `esteid-ldap-sk-ee.der` | `esteid.ldap.sk.ee` server certificate, valid to 2027-05-19, as served on 2026-11-20 | `b60e61a7a6ec109c3e864aa905e414bc79b56e55f7a65b0675f7c2a551f2a200` |
| `digicert-global-g2-tls-rsa-sha256-2020-ca1.der` | DigiCert Global G2 TLS RSA SHA256 2020 CA1, the intermediate `esteid.ldap.sk.ee` sends with it | `c8025f9fc65fdfc95b3ca8cc7867b9a587b5277973957917463fc813d0b625a9` |
| `digicert-global-root-g2.der` | DigiCert Global Root G2 | `cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f` |
| `usertrust-rsa-root.der` | USERTrust RSA Certification Authority: an unrelated root, used to show that a chain is rejected without its own root | `e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2` |

The tests verify at a fixed time, so they keep passing after the server certificate expires.

These are a snapshot, so they cannot notice SK reissuing its certificate or leaving its
intermediate out again. The live check `scripts/check-directory-chain.sh` covers that.
