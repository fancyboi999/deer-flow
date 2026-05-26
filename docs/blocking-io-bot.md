# Blocking-IO PR comment bot

A reference workflow that turns the static blocking-IO scanner from PR #3208
into a per-PR review aid. Modelled after `open-design/visual-pr-comment` — no
third-party Actions, bare `gh api`, sentinel-based comment upsert.

## Goals

This workflow exists to resolve the trade-off discussed in PR #3208:

- **Author's concern** — gating CI on a static scanner produces false-positive
  failures and blocks unrelated PRs.
- **Maintainer's concern** — a tool that ships without enforcement is a tool
  nobody runs.

The bot resolves both by surfacing findings as **PR comments** rather than
checks:

- Every PR gets a single, auto-updated comment summarising new candidates.
- Reviewers see findings inline on the PR they're already reviewing — no need
  to remember to run `make detect-blocking-io` locally.
- The PR never fails because of this scan. Historical debt (the current 97
  fingerprints in baseline) does not appear in the new-findings table.

The baseline file is the load-bearing piece: it freezes pre-existing findings
so the comment only highlights what *this PR* introduced.

## How it works

```
pull_request event
   │
   ▼
make detect-blocking-io  ──▶  .deer-flow/blocking-io-findings.json   (current scan)
   │
   ▼
format_blocking_io_comment.py
   │
   ├─ load current findings
   ├─ load .deer-flow/blocking-io-baseline.json    (frozen fingerprints)
   ├─ diff  → new = current − baseline
   │           fixed = baseline − current
   │           unchanged = baseline ∩ current
   └─ emit markdown                                  → .deer-flow/blocking-io-comment.md
   │
   ▼
gh api list comments
   │
   ├─ found "<!-- blocking-io-bot -->" marker?  →  PATCH that comment
   └─ otherwise                                  →  POST new comment
```

Fingerprint format is `path|function|symbol|operation`. Line numbers are
deliberately *not* part of the fingerprint — they drift with unrelated edits
and would otherwise create churn in the new-findings table.

## Files

| Path | Purpose |
|---|---|
| `.github/workflows/blocking-io-comment.yml` | The workflow itself. Trigger: `pull_request`, also manual `workflow_dispatch`. Permissions: `pull-requests: write`. |
| `scripts/format_blocking_io_comment.py` | Pure-stdlib renderer that diffs the scan against the baseline and emits markdown. |
| `.deer-flow/blocking-io-baseline.json` | Frozen set of fingerprints. Refresh when historical debt is paid down. |
| `scripts/detect_blocking_io_static.py` | The scanner from PR #3208 (unchanged). |

## Operating the baseline

Update the baseline whenever a batch of historical findings is genuinely fixed
(not just refactored away):

```bash
make detect-blocking-io
python3 -c "
import json
findings = json.load(open('.deer-flow/blocking-io-findings.json'))
fps = sorted({
    '|'.join([
        f['location']['path'],
        f['location'].get('function') or '<module>',
        f['blocking_call']['symbol'],
        f['blocking_call']['operation'],
    ]) for f in findings
})
import json as _j
doc = _j.load(open('.deer-flow/blocking-io-baseline.json'))
doc['fingerprints'] = fps
doc['generated_from'] = 'main @ <sha>'
_j.dump(doc, open('.deer-flow/blocking-io-baseline.json', 'w'), indent=2)
"
git add .deer-flow/blocking-io-baseline.json
git commit -m "chore(blocking-io): refresh baseline after debt cleanup"
```

A standalone `scripts/refresh_blocking_io_baseline.py` helper is the natural
next step if the above becomes routine.

## Switching to a gating mode (future)

The workflow today is purely advisory. If maintainers eventually decide
new findings should block merging, the change is two lines:

```yaml
- name: Fail on new findings
  if: steps.diff.outputs.new_count != '0'
  run: |
    echo "::error::This PR introduces new blocking-IO candidates. See the bot comment."
    exit 1
```

…and exposing `new_count` from the format script. Keeping these tiers separate
makes it easy to start advisory and graduate to gating once the team is
comfortable with the false-positive rate.

## Why bare `gh api`?

Looked at three popular options before committing:

| Option | Trade-off |
|---|---|
| Bare `gh api` + sentinel (chosen) | 0 third-party deps, small audit surface, matches `open-design`'s existing pattern, ~20 lines of shell. |
| [`peter-evans/create-or-update-comment`](https://github.com/peter-evans/create-or-update-comment) | 6-line declarative usage but adds a third-party Action to review. |
| `actions/github-script` (octokit-in-yaml) | Flexible but the JS-in-YAML grows hard to read once branching is added. |

For a single-comment upsert with no other interactions, the shell version is
easier to audit and matches `open-design`'s established style.
