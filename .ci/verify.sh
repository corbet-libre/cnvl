#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
: "${CI_COMMIT_SHA:?verify requires the exact source revision}"
: "${ARTIFACT_ROOT:?verify requires an absolute ARTIFACT_ROOT}"
[[ "$ARTIFACT_ROOT" = /* ]] || { echo "ARTIFACT_ROOT must be absolute" >&2; exit 2; }
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"
python3 .github/scripts/check-lock.py
python3 .github/scripts/test-lock.py
rustc --version --verbose
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
node --test .github/scripts/test-auto-merge.mjs
python3 .github/scripts/test-coverage.py
cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings
wasm-pack test --headless --chrome -- --locked
rustup run nightly rustc --version
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
"$NIGHTLY_CARGO" llvm-cov --version
"$NIGHTLY_CARGO" llvm-cov --locked --branch --json --output-path coverage.json --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --lcov --output-path coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --text --output-path coverage.txt --ignore-filename-regex '/tests/'
python3 .github/scripts/check-coverage.py coverage.lcov coverage.json coverage.txt
clang --version
version=$(python3 -c "import tomllib; print(next(p['version'] for p in tomllib.load(open('Cargo.lock','rb'))['package'] if p['name']=='wasm-bindgen'))")
wb_archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
wb_base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}"
mkdir -p "$RUNNER_TEMP/wasm-bindgen-cli"
(cd "$RUNNER_TEMP/wasm-bindgen-cli" && curl --fail --location --retry 3 --remote-name "$wb_base/$wb_archive" && curl --fail --location --retry 3 --remote-name "$wb_base/$wb_archive.sha256sum" && wb_checksum=$(cut -d ' ' -f1 "$wb_archive.sha256sum") && printf '%s  %s\n' "$wb_checksum" "$wb_archive" | sha256sum --check && tar -xzf "$wb_archive" --strip-components=1)
export PATH="$RUNNER_TEMP/wasm-bindgen-cli:$PATH"
python3 -m pip install -r .github/requirements.txt
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="python3 .github/scripts/browser-coverage-runner.py"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-Zno-profiler-runtime -Clink-args=--no-gc-sections --cfg=owned_browser_coverage"
export WASM_BINDGEN_TEST_ONLY_WEB=1 WASM_BINDGEN_SPLIT_LINKED_MODULES=1 CC_wasm32_unknown_unknown=clang
export CHROMEDRIVER="$(command -v chromedriver)"
test -x "$CHROMEDRIVER" || { echo "chromedriver not on PATH" >&2; exit 2; }
"$NIGHTLY_CARGO" llvm-cov test --locked --branch --coverage-target-only --target wasm32-unknown-unknown --json --output-path wasm-coverage.json --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --lcov --output-path wasm-coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --text --output-path wasm-coverage.txt --ignore-filename-regex '/tests/'
python3 .github/scripts/check-coverage.py wasm-coverage.lcov wasm-coverage.json wasm-coverage.txt wasm
