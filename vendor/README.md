# VENDORED DEPENDENCIES

XRPMAN Rekey V8 ships its only runtime dependency in-tree. Nothing is fetched from a CDN at runtime, so
the Content-Security-Policy can be `default-src 'none'` with no third-party origins, and the wizard runs
on an air-gapped machine.

## xrpl-5.2.0.min.js

| | |
|---|---|
| Package | `xrpl` |
| Version | `5.2.0` |
| Artifact | `build/xrpl-latest-min.js` (UMD browser bundle, exposes global `xrpl`) |
| Origin | `https://cdn.jsdelivr.net/npm/xrpl@5.2.0/build/xrpl-latest-min.js` |
| Size | 555614 bytes |
| SHA-384 (SRI) | `sha384-/iUqnSBI9CjqjXUCmLgmJojnUOaOWE7dFjwmLkgHBIAOVohrPrUfMadmCBIL5iiX` |
| SHA-256 | `8a227bcbf337099b281de3f2e6cf6a214f7746b59e8520eb19108e40d8e9210a` |

### Verify this file yourself

```sh
curl -sL https://cdn.jsdelivr.net/npm/xrpl@5.2.0/build/xrpl-latest-min.js \
  | openssl dgst -sha256 -hex
# must print: 8a227bcbf337099b281de3f2e6cf6a214f7746b59e8520eb19108e40d8e9210a

openssl dgst -sha256 -hex vendor/xrpl-5.2.0.min.js
# must print the same
```

The browser bundle already carries its own `buffer` shim, so V7's `buffer@6.0.3` polyfill is gone. V7's
`bip39` script was a web-worker bundle loaded as a classic script and referenced nowhere — also gone.

### Upgrading

1. Download the new `build/xrpl-latest-min.js`.
2. Recompute both digests and update this file.
3. Re-run `node tests/run.js` — the derivation vectors there pin cross-version behaviour, including the
   secp256k1/ed25519 default that changed between xrpl 2.x and 5.x (see `docs/V7-AUDIT.md`, F14).
