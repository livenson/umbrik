# Interop testing

The only test that catches a wrong salt, a misaligned AAD range, or an HKDF backed by the wrong
hash — a constant applied consistently in both directions passes a round trip. A CI gate, not a
nice-to-have.

## What it checks

Both directions, for every implemented scheme:

- `umbrik encrypt` -> `cdoc2-cli decrypt`, contents byte-identical
- `cdoc2-cli encrypt` -> `umbrik decrypt`, contents byte-identical

## Running locally

```bash
tests/interop/run.sh
```

Builds the reference CLI image on first run (several minutes), then reuses it.

### Apple Silicon

The reference build runs an x86_64 `flatc` binary, which fails natively on arm64:

```
rosetta error: failed to open elf at /lib64/ld-linux-x86-64.so.2
```

`run.sh` therefore builds and runs the image as `linux/amd64` under emulation. It is slower but
correct. GitHub's x86_64 runners are unaffected.

## Why the image builds three repositories

`cdoc2-java-ref-impl` cannot be built from Maven Central alone. Two of its dependencies are
published only to GitHub Packages, which would mean requiring a token just to run the tests.
Both are built from source instead:

| Artifact | Source | Why |
|---|---|---|
| `ee.cyber.cdoc2.openapi:cdoc2-key-capsules-openapi:yaml` | `open-eid/cdoc2-openapi` | `cdoc2-client` generates its server client from it. The version is declared inside the YAML (`info.version`), and the repo's `install-file` executions place it in the local repository. |
| `ee.cyber.cdoc2:cdoc2-auth-token` | `open-eid/cdoc2-auth` | Compile dependency of `cdoc2-lib`. |

`cdoc2-auth` is pinned to a **`develop`** commit, not `master`: `cdoc2-lib` requires
`cdoc2-auth-token` 0.7.2, and `master` is still on 0.3.3. It is pinned by SHA, so the moving
branch does not make the build non-reproducible.

## Pinning

Every `*_REF` in the `Dockerfile` is a commit SHA. Bump them deliberately, and treat a resulting
failure as a real finding rather than something to work around.

If a bump fails to resolve a dependency, check whether another GitHub-Packages-only artifact has
appeared in the chain — that is the usual cause, and the fix is another source build here rather
than a credential.
