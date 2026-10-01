# Coverage contract

CI measures production Rust lines and branches with cargo-llvm-cov and requires
100% of both. A zero-count report fails. Test harness files are excluded from the
production denominator. No production paths are excluded at this stage. Browser
vectors execute in headless Chrome; a compile check is not execution evidence.
Native coverage does not establish coverage of wasm-only adapters.

Stable Rust runs product validation. Nightly is used only for upstream Rust's
experimental branch instrumentation. CI resolves dependencies once and uploads
Cargo.lock; all jobs consume that exact snapshot with --locked. Weekly CI refreshes
the snapshot and Dependabot proposes manifest/lock updates. A failed coverage gate
is an open requirement, never evidence of complete coverage.

## Unreachable defensive mappings

The gate reads LLVM LCOV line/branch evidence, with exactly two defensive error
mapping lines excluded. They remain in production as fail-closed safeguards:

- `ReadKey::unwrap`: the input must be 72 bytes before ckmg opens it. Its
  construction is a 24-byte nonce, a 32-byte secret and a 16-byte Poly1305 tag.
  Successful authentication therefore gives precisely 32 bytes. A conversion
  error would require an upstream size-contract defect. The native and browser
  custody vector performs real wrapping, restoration, wrong-context and bad-length
  refusals, and opens the original envelope after restoration.
- `seal`: RustCrypto `chacha20poly1305` encryption rejects message sizes beyond
  the ChaCha block counter bound. The public 1 MiB precondition is smaller by
  several orders of magnitude. The real maximum-size vector and over-limit
  refusal run on native and browser. Allocation failure aborts and does not
  produce this `Result` error.

The JSON allowlist pins file, line and exact source, requires rationale/evidence,
and rejects stale or exercised exclusions. The gate still requires 100% of
reachable lines and every measured branch; it prints raw excluded locations.
No whole function, crypto operation, format check, authentication error, entropy
failure or browser vector is excluded. These two justifications require the
same independent security review as the implementation; CI is not acceptance.
