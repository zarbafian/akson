# xcheck — independent vector cross-checker

Re-derives every golden vector under `spec/vectors/` with Python
implementations that share no code with the Rust workspace:

- JCS canonicalization: [`rfc8785`](https://pypi.org/project/rfc8785/)
- JWK thumbprints: [`jwcrypto`](https://pypi.org/project/jwcrypto/)
- Ed25519: [`cryptography`](https://pypi.org/project/cryptography/)

CI runs this against the frozen vectors on every push; the Rust test suites
(`crates/*/tests/vectors.rs`) reproduce the same vectors from the other side.
A vector is trustworthy only while both sides derive it independently.

~~~text
python3 -m venv --without-pip xcheck/.venv   # or any venv/pip you have
xcheck/.venv/bin/pip install -r xcheck/requirements.txt
xcheck/.venv/bin/python xcheck/run.py spec/vectors
~~~

This already paid for itself: the `jcs/utf16-key-sorting` vector caught
`serde_jcs` sorting object keys by code point instead of RFC 8785's UTF-16
code units, which is why the workspace uses `json-canon` (ADR-0001 appendix).
