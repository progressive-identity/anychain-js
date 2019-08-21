# anychain-js

Provides basic blocks to build and work with cryptographic chains.

- Based on robust cryptographic routines with `libsodium.js` (Blake2b, Ed25519).
- JSON objects casted as merkle tree: any value in an object or array may be
  replaced by its hash without changing the object/array's hash.
- Encrypt and sign objects.
- Serialize/Deserialize object in JSON, URL-encoded string or binary.
- Easy (secret) key derivation.

It is one single file developed in EMCAScript 2017+, works in the browser & node.
