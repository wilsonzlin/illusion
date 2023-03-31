# Illusion

Get, put, and list objects on an S3-compatible service using client-side encryption. Run the Illusion local HTTP server, provide a strong master password, and make RESTful calls to GET and PUT */key* to interact with objects as usual. The local Illusion server will transparently encrypt and decrypt object keys and data, even for partial range requests.

## Important details

- If the master password is lost, all data will be lost.
- There is no verification of the master password; entering an incorrect password will likely lead to object keys being mismatched.
