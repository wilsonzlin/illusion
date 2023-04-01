# Illusion

Get, put, and list objects on an S3-compatible service using client-side encryption.

Run the Illusion local HTTP server and make requests to GET and PUT */key* to interact with objects as usual. The local Illusion server will transparently encrypt and decrypt object keys and data, even for partial range requests.

This is useful for hiding object keys and contents from others who have access to the bucket and/or objects, including the S3 service itself.

What this **doesn't protect**:

- Anything, if the master password is weak or leaked.
- Transport layer attacks, if the connection to the S3 service is insecure.
- Size of object keys and contents.
- How many objects exist and when they were created and last updated.
- Who created the objects.
- Data being rearranged or truncated by someone with access to the objects or the S3 service itself.

Use this at your own risk.

## Important details

- If the master password is lost, all data will be lost.
- There is no verification of the master password; entering an incorrect password will likely lead to object keys being mismatched and possibly data being corrupted.
