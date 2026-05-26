#!/usr/bin/env python3
"""Render the blocking-IO scanner findings into a PR comment markdown body.

Diffs the current scan against a frozen baseline so the PR comment focuses on
*new* findings introduced by the change. Pre-existing debt is collapsed into a
folded summary so the reviewer is not buried under it.

Usage:
    python scripts/format_blocking_io_comment.py \
        --findings .deer-flow/blocking-io-findings.json \
        --baseline .deer-flow/blocking-io-baseline.json \
        --output .deer-flow/blocking-io-comment.md \
        --head-sha "$GITHUB_SHA" \
        --base-sha "$BASE_SHA" \
        --run-url "$RUN_URL"
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SENTINEL = "<!-- blocking-io-bot -->"

PRIORITY_BADGE = {
    "HIGH": "🔴 HIGH",
    "MEDIUM": "🟡 MED",
    "LOW": "🟢 LOW",
}
PRIORITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def fingerprint(finding: dict[str, Any]) -> str:
    """Stable identity that survives line-number drift inside a function."""
    loc = finding["location"]
    call = finding["blocking_call"]
    return "|".join(
        [
            loc["path"],
            loc.get("function") or "<module>",
            call["symbol"],
            call["operation"],
        ]
    )


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def render(  # noqa: PLR0913
    *,
    findings: list[dict[str, Any]],
    baseline_fps: set[str],
    head_sha: str,
    base_sha: str,
    run_url: str | None,
) -> str:
    current_by_fp: dict[str, dict[str, Any]] = {fingerprint(f): f for f in findings}
    current_fps = set(current_by_fp.keys())

    new_fps = current_fps - baseline_fps
    fixed_fps = baseline_fps - current_fps
    unchanged_fps = current_fps & baseline_fps

    new_findings = sorted(
        (current_by_fp[fp] for fp in new_fps),
        key=lambda f: (
            PRIORITY_ORDER.get(f["priority"], 99),
            f["location"]["path"],
            f["location"]["line"],
        ),
    )

    lines: list[str] = []
    lines.append(SENTINEL)
    lines.append("## Blocking I/O scanner")
    lines.append("")

    head_short = head_sha[:7] if head_sha else "unknown"
    base_short = base_sha[:7] if base_sha else "unknown"
    header_bits = [f"**Head**: `{head_short}`", f"**Base**: `{base_short}`"]
    if run_url:
        header_bits.append(f"[Run logs ↗]({run_url})")
    lines.append(" · ".join(header_bits))
    lines.append("")

    lines.append(
        "> Advisory only — this scanner identifies *static candidates* for "
        "human review. Runtime event-loop impact is not proven. **This comment "
        "does not block merging.**"
    )
    lines.append("")

    status_bits = []
    if new_fps:
        status_bits.append(f"**+{len(new_fps)} new**")
    else:
        status_bits.append("**+0 new**")
    status_bits.append(f"{len(unchanged_fps)} unchanged")
    if fixed_fps:
        status_bits.append(f"**−{len(fixed_fps)} fixed** 🎉")
    else:
        status_bits.append("−0 fixed")
    lines.append(" · ".join(status_bits))
    lines.append("")

    if new_findings:
        lines.append("### New findings introduced by this PR")
        lines.append("")
        lines.append("| Priority | Location | Operation | Exposure | Reason |")
        lines.append("|---|---|---|---|---|")
        for f in new_findings:
            loc = f["location"]
            call = f["blocking_call"]
            func = loc.get("function") or "<module>"
            location_cell = f"`{loc['path']}:{loc['line']}` in `{func}`"
            op_cell = f"`{call['symbol']}` ({call['operation']})"
            exposure_cell = call.get("category", "—")
            row = (
                f"| {PRIORITY_BADGE.get(f['priority'], f['priority'])} "
                f"| {location_cell} "
                f"| {op_cell} "
                f"| `{f['event_loop_exposure']}` "
                f"| {f['reason']} |"
            )
            lines.append(row)
            _ = exposure_cell  # category already encoded in op_cell context
        lines.append("")
    else:
        lines.append("### No new blocking-IO candidates introduced 🎉")
        lines.append("")
        lines.append(
            "Static scan did not detect any new blocking calls reachable from "
            "the event loop in this PR's diff."
        )
        lines.append("")

    lines.append(f"<details><summary>📊 Baseline ({len(baseline_fps)} pre-existing)</summary>")
    lines.append("")
    if baseline_fps and findings:
        baseline_findings = [
            current_by_fp[fp] for fp in unchanged_fps if fp in current_by_fp
        ]
        prio_counts = Counter(f["priority"] for f in baseline_findings)
        exp_counts = Counter(f["event_loop_exposure"] for f in baseline_findings)
        cat_counts = Counter(f["blocking_call"]["category"] for f in baseline_findings)

        lines.append("| Category | HIGH | MED | LOW | Total |")
        lines.append("|---|---:|---:|---:|---:|")
        for cat, total in cat_counts.most_common():
            cat_findings = [
                f for f in baseline_findings if f["blocking_call"]["category"] == cat
            ]
            cat_prio = Counter(f["priority"] for f in cat_findings)
            lines.append(
                f"| {cat} "
                f"| {cat_prio.get('HIGH', 0)} "
                f"| {cat_prio.get('MEDIUM', 0)} "
                f"| {cat_prio.get('LOW', 0)} "
                f"| {total} |"
            )
        lines.append("")
        lines.append(
            "By exposure: "
            + " · ".join(f"{n} `{exp}`" for exp, n in exp_counts.most_common())
        )
        lines.append("")
        _ = prio_counts
    else:
        lines.append("_No baseline recorded yet._")
        lines.append("")
    lines.append("</details>")
    lines.append("")

    lines.append("### Reproduce locally")
    lines.append("")
    lines.append("```bash")
    lines.append("make detect-blocking-io")
    lines.append("# writes .deer-flow/blocking-io-findings.json")
    lines.append("```")
    lines.append("")
    lines.append(
        "See [backend/CLAUDE.md](../blob/main/backend/CLAUDE.md) for "
        "detection scope and scoring."
    )

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--head-sha", default="")
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--run-url", default="")
    args = parser.parse_args(argv)

    findings = load_json(args.findings)
    if not isinstance(findings, list):
        print("findings file must be a JSON array", file=sys.stderr)
        return 2

    baseline_doc = load_json(args.baseline)
    baseline_fps = set(baseline_doc.get("fingerprints", []))

    body = render(
        findings=findings,
        baseline_fps=baseline_fps,
        head_sha=args.head_sha,
        base_sha=args.base_sha,
        run_url=args.run_url or None,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(body, encoding="utf-8")
    print(f"Wrote {args.output} ({len(body)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
