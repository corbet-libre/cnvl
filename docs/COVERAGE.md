# Coverage contract

CI measures production Rust lines and branches with cargo-llvm-cov and requires
100% of both. A zero-count report fails. Test harness files are excluded from the
production denominator. Browser
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

Actual browser Rust coverage runs the same owner vectors through wasm-bindgen
minicov on current nightly. Upstream instrumentation failures remain red and
are reported separately from stable browser execution.
Stable Rust separately builds and executes the product vectors. Native and wasm
line/branch gates are independent; neither substitutes for the other. LCOV
merges generic instantiations at the source-line boundary and preserves every
measured branch. The JSON report remains available as diagnostic evidence.

## Current browser profiling runtime

The test-only `.github/coverage-runtime` adapter calls maintained minicov directly
from its maintained upstream master branch. wasm-bindgen-test currently fixes its optional
profiling dependency to minicov 0.3.8 for LLVM 22; current minicov implements the
LLVM 23 profile format. The CI job reports compiler/runtime versions, disables
only wasm-bindgen-test's obsolete optional profiler, and instruments the same
real browser tests. Selenium drives the original upstream test server, waits for
all tests, invokes the tiny test-only capture binding, and waits for the original
server's successful nonempty profile upload before closing Chrome. LLVM still
parses and checks the actual raw profile and enforces every measured line/branch.
No production API, counter implementation, profile format, synthetic report or
version impersonation is introduced. A version mismatch or missing capture fails.

Current cargo-llvm-cov supplies instrumentation through its workspace wrapper.
The target flags deliberately omit a duplicate global `-Cinstrument-coverage`,
which would also instrument foreign standalone cdylibs without a test runtime.
Every owned source file and test target remains instrumented by the maintained
wrapper; third-party source is outside this library's coverage denominator.

Current LLVM23 reports the two documented unreachable defensive mappings as
uncovered on both native and wasm. The source-pinned justifications apply to
both targets. Earlier LLVM22 attributed these spans differently; no compiler
pin or threshold change is used to hide that difference.

The published minicov 0.3.9 semver range was tested with wasm-bindgen-test 0.3.79.
Cargo refuses its overlap with the runner's optional exact minicov 0.3.8. With an
older unrestricted test range it instead downgraded wasm-bindgen-test to 0.3.45;
that is explicitly rejected. The test harness requires the current 0.3.79-or-newer
protocol. A separate upstream git source is used solely to separate these Cargo
package identities. The obsolete runner profiler is disabled; only the maintained
current runtime is linked into the instrumented test. There is no patched version
number, compiler pin or product dependency on this helper.
