# libssh2 resource fixes

This overlay retains libssh2 1.11.1 and the pinned vcpkg port recipe, with two
resource ownership fixes in `resource-fixes.patch`:

- `mac_method_none_init` (integrated AES-GCM authentication) must tell the KEX
  caller to free the derived MAC key that the no-op MAC does not retain.
  Without this, Curve25519/SHA-256 KEX loses two 48-byte allocations per session.
- `_libssh2_ecdh_gen_k` must free its OpenSSL 3 `BN_CTX`, key import context and
  original reference to the imported peer public key on all exit paths.

The local port version is 2. `vcpkg-configuration.json` selects the overlay;
the global vcpkg checkout and the upstream dependency versions are unchanged.
`tests/resource_stress.py` checks live Debug CRT allocations and Windows handles
for ordinary transfers, reconnects and delayed SFTP file/directory close replies.
