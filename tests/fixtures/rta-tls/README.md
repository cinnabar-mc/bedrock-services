# Original loopback TLS fixture

These original self-signed P-256 test certificates identify only `localhost`.
The included unencrypted server key is deliberately public synthetic test data,
never a production credential. The signing root private key was discarded.
The certificates are valid for 100 years from fixture creation in October 2026.

Tests install this root only in their private connector. The production edge
uses public WebPKI roots, verifies its fixed service hostname, and exposes no
trust override or plaintext constructor.
