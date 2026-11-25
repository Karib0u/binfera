Synthetic family packs for `check-family-wasm.mjs`, built from `web/public/demo.exe` with the
`binfera::family` writer (the same tables as `layered_bxfam003_packs_through_cli_and_mcp` in
`binfera-cli/tests/family.rs`). They hold no malware data.

- `demo-v2.bxfam`: `BXFAM002`, family `win.synthetic` = demo.exe's two largest functions.
- `demo-base.bxfam`: `BXFAM003`, the same family plus three exclusive malware strings and one Trusted string.
- `demo-org-trusted.bxfam`: `BXFAM003` overlay that trusts the largest function and the third largest
  (`openssl`), with the Trusted symbols `OrgTrustedHelper` and `EVP_DecryptUpdate`.
