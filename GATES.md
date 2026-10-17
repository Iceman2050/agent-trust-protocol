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
