# Acceptance Gates — agent-trust-protocol (unlazy)

Written FIRST, proven with runnable checks. A gate counts as met only when the
check command exits zero AND the expected evidence is present.

| # | Gate | Check command | Expected evidence |
|---|------|---------------|-------------------|
| 1 | Full test suite green on my run | `python3 -m unittest discover -s tests` from repo root | exit 0; N tests, "OK" in output |
| 2 | All 5 required test cases exist and pass | `python3 -m unittest discover -s tests -v` | attestation round-trip; tampered rejection; handshake refusal; replay rejection; audit integrity |
| 3 | README example output byte-matches a fresh demo run | `python3 demo.py > /tmp/demo_fresh.txt` then diff against the README fenced block | diff exits 0 (deterministic demo output) |
| 4 | MIT LICENSE present and non-empty | `test -s LICENSE` | exit 0 |
| 5 | CI YAML valid + runs the real test command | `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`; grep for the unittest command | exits 0; command present |
| 6 | No secrets in the tree | `grep -rEi '(api[_-]?key|secret|token|password|private[_-]?key)' --include='*.py' --include='*.md' . \| grep -vi -e 'LICENSE_SECRET' -e 'production' ` | only intended mentions (e.g. "shared secret" in spec/docs); no real credential values |
| 7 | gh repo create attempted AT MOST once; on 429 throttle → PUSH-PENDING | shell log of the single attempt | public URL or PUSH-PENDING, no retry loops |

Gate results recorded below on completion.

## Results (2026-10-17, run by builder)

| # | Result |
|---|--------|
| 1 | PASS — `python3 -m unittest discover -s tests` → 13 tests, OK, exit 0 |
| 2 | PASS — all 5 required cases present and green: attestation round-trip, tampered rejection, handshake refusal (incompatible perms), session replay rejection (+ out-of-order), audit integrity (tamper detection + hash chaining) |
| 3 | PASS — `diff` of README fenced demo block vs fresh `python3 demo.py` run: byte-identical (demo seeded for determinism) |
| 4 | PASS — `test -s LICENSE` exit 0 (MIT, Ingenious AI 2026) |
| 5 | PASS — CI YAML parses (PyYAML); runs `python -m unittest discover -s tests -v`, the repo's real test command |
| 6 | PASS — no secrets in tree; only clearly-labeled demo/test keys (`DEMO ONLY`, `test-shared-key`) |
| 7 | PASS — single `gh repo create` succeeded first try → https://github.com/Iceman2050/agent-trust-protocol (public, pushed, 5 topics set). No retry loop needed. |

Bugs found and fixed during the build: (1) handshake granted each party's requests against the wrong party's attested permissions — rewrote the intersection logic; (2) stateless `Session.receive` couldn't detect exact replays — made it an instance method tracking the next expected inbound seq.
