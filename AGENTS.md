# cnvl agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run from the lane root (`<lane>/ws`); `cbuild <lane> ...` builds there.

Build and test (quote the verdict line, never infer from a pipe):
- `cbuild <lane> fmt -p cnvl -- --check` — must be clean
- `cbuild <lane> test -p cnvl --locked` — `envelope` `5`, doc `4` passed, exit 0; long, background it
- `cbuild <lane> clippy -p cnvl --locked --all-targets -- -D warnings` — exit 0
- `cbuild <lane> check -p cnvl --locked --target wasm32-unknown-unknown` — exit 0
- Full gate (wasm-pack browser exec, 100% line+branch coverage) runs in CI; see `.github/workflows/ci.yml`, `docs/COVERAGE.md`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Exact signed bytes round-trip; private values and keys never enter forum traffic
  -> `tests/envelope.rs::round_trip_exact_bytes_and_vault_custody`
- Every context component and format bound; changed context refused
  -> `::every_context_component_and_format_is_bound`
- Bounds and wrong custody fail closed; no key/nonce reuse
  -> `::bounds_and_wrong_custody_fail_closed`
- Wrapped local custody restores only under the same purpose/member/community/context
  -> `::encrypted_local_custody_and_remaining_bounds`
- A room grant is adopted only from its owner and stays scoped to that room
  -> `::a_room_grant_is_adopted_only_from_its_owner_and_is_scoped_to_the_room`

Pointers: `src/custody.rs`, `src/lib.rs`, `docs/CONTRACT.md`, `docs/COVERAGE.md`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking-exception; no GPL/AGPL-only deps.
