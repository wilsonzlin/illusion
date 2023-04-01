# Illusion

Upload and download objects to/from an S3-compatible service with transparent client-side encryption.

Run the Illusion local HTTP server and make requests to GET and PUT */key* to interact with objects as usual. The local Illusion server will transparently encrypt and decrypt object keys and data, even for partial range requests.

This is useful for hiding object keys and contents from others who have access to the bucket and/or objects, including the S3 service itself.

What this **doesn't protect**:

- Anything, if the master password is weak or leaked.
- Transport layer attacks, if the connection to the S3 service is insecure.
- Size of object keys and contents.
- How many objects exist and when they were created and last updated.
- Who created the objects.
- Data being rearranged or truncated by someone with access to the objects or the S3 service itself.

It's not possible to list objects due to the way object keys are encrypted. It's unlikely to be useful anyway, as the order would be random, and a full scan would be needed most of the time. Tracking the object list via a separate encrypted database is one workaround.

Use this at your own risk.

## Important details

- If the master password is lost, all data will be lost.
- There is no verification of the master password; entering an incorrect password will likely lead to object keys being mismatched and possibly data being corrupted.

## Encryption mechanism

- PBKDF2 with HMAC-SHA512 and 650,000 rounds is used to derive two 256-bit keys.
- One key is used as the IKM to HKDF with SHA256, which is used to expand 256-bit keys to encrypt object keys.
  - These keys encrypt object keys with ChaCha2020-Poly1305 and a fixed nonce of zero.
- The other key is used as the IKM to HKDF with SHA256, which is used to expand 256-bit keys to encrypt object contents.
  - These keys encrypt each 64 KiB chunk of the object contents with XChaCha2020-Poly1305 and a crypto-random 192-bit nonce.
