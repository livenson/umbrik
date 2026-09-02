# umbrik

Python bindings for [umbrik](https://github.com/livenson/umbrik) — read and write **CDOC2**
encrypted containers, the Estonian `.cdoc2` format.

> Not affiliated with or endorsed by RIA or Cybernetica. An independent implementation of a
> published open specification. **Unaudited**, and provided without warranty.

## Install

The package is not on PyPI yet. Download the wheel for your platform from the
[release page](https://github.com/livenson/umbrik/releases/latest) and install it:

```bash
pip install ./umbrik-*.whl
```

Wheels are built against Python's stable ABI (`abi3`), so a single wheel per platform works on
**Python 3.10 and every later version** — including versions released after the wheel was.

## Use

```python
import umbrik

# Encrypt with a password
blob = umbrik.encrypt({"notes.txt": b"tere"}, password=("my-label", "hunter2"))

# ... a pre-shared 32-byte key
blob = umbrik.encrypt({"notes.txt": b"tere"}, secret=("my-label", key_bytes))

# ... or to a recipient's certificate (PEM or DER)
blob = umbrik.encrypt({"report.pdf": data}, certificate=cert_bytes)

# Decrypt — returns {name: contents}
files = umbrik.decrypt(blob, password="hunter2")

# See who a container is addressed to; needs no key
for r in umbrik.recipients(blob):
    print(r.scheme, r.display)   # SC01 TESTIJA,MARI,00000000000 (ID-card)
```

## Errors

Exceptions distinguish the cases you would handle differently:

```python
try:
    files = umbrik.decrypt(blob, password=pw)
except umbrik.WrongKeyError:
    ...   # wrong password, or the container was tampered with
except umbrik.NoMatchingRecipientError:
    ...   # addressed to somebody else entirely
except umbrik.LimitExceededError:
    ...   # tripped a safety limit, e.g. compression ratio
```

All inherit from `umbrik.UmbrikError`.

## Limits

Extraction enforces limits against hostile containers — compression ratio, entry count,
uncompressed size — and rejects path traversal, absolute paths and symlinks. Raise them only for
a container you trust:

```python
files = umbrik.decrypt(blob, password=pw,
                       limits=umbrik.Limits(max_compression_ratio=1000))
```

## Threading

The GIL is released for password-based operations, which run 600 000 PBKDF2 iterations and would
otherwise block the interpreter.

## Scope

Implemented: **SC05** (pre-shared key), **SC06** (password), **SC01** (ECDH), **SC02**
(RSA-OAEP). Decryption with a smart card is available through the `umbrik` command-line tool
rather than this package.
