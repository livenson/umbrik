# Test fixtures

Public certificates for the offline chain-verification tests in `src/lib.rs`. None of them is
used at run time. The intermediate those tests rely on is in `../certs/`.

| File | Certificate | SHA-256 of the DER |
|---|---|---|
| `esteid-ldap-sk-ee.der` | `esteid.ldap.sk.ee` server certificate, valid to 2027-05-19, as served on 2026-11-20 | `b60e61a7a6ec109c3e864aa905e414bc79b56e55f7a65b0675f7c2a551f2a200` |
| `digicert-global-root-g2.der` | DigiCert Global Root G2 | `cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f` |
| `usertrust-rsa-root.der` | USERTrust RSA Certification Authority: an unrelated root, used to show that the bundled intermediate is not a trust anchor | `e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2` |

The tests verify at a fixed time, so they keep passing after the server certificate expires.
