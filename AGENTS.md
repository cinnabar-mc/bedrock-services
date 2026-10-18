# Repository instructions

Follow maintainer-local instructions when present. Keep research and agent reports
privately. Public builds require no private resources.

Use idiomatic Rust ownership and typed errors. Preserve accurate attribution.
Document helper contracts. Keep pure signing/expiry logic clock-free; the HTTP
edge owns clock reads. Do not log credentials or include raw response bodies in
errors. Keep acquisition separate from authorized service traffic.

Run focused tests and clippy through the configured shared build limiter.
Changes target `dev` through reviewed PRs. Do not claim live-account acceptance or
vanilla parity from synthetic HTTP tests or third-party source alone.
