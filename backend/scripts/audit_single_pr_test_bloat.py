#!/usr/bin/env python3
"""Audit backend tests for single-PR, single-spot-defense bloat and low-ROI patterns.

Identifies standalone ``backend/tests/test_*.py`` files that exhibit a combination of:

1. **Single-PR micro-patch origin**: created in a narrow ``fix(...)`` commit (few production
   files and lines changed) with a disproportionate ``test_lines / prod_churn`` bloat ratio,
   and rarely or never modified afterward.
2. **AST coupling & boilerplate smells**: heavy mocking (``MagicMock``/``patch``/``monkeypatch``),
   ``assert_called*`` checks, private (``_name``) symbol imports, or large fake/stub scaffolding.
3. **Optional dynamic coverage & CI history join** (``--coverage-csv``): per-test unique
   line/branch counts and historical CI failure counts.
4. **High-risk guardrail tagging**: separates security, auth, isolation, migration, concurrency,
   and cancellation-drain tests from routine low-ROI micro-defense candidates.

Usage:
    uv run python scripts/audit_single_pr_test_bloat.py --top 30
    uv run python scripts/audit_single_pr_test_bloat.py --coverage-csv path/to/per-test.csv --format markdown
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

HIGH_RISK_RE = re.compile(
    r"(auth|security|ssrf|secret|token|pat_|csrf|xss|sql|inject|perm|acl|rbac|"
    r"sandbox_security|executable_gate|skillscan|cross_owner|safety_responses|"
    r"migration|alembic|postgres|lock|atomic|lease|ownership|isolation|tenant|"
    r"race|fence|cancellation|idempotency|concurrency|pipe_fd|blocking_io|"
    r"bundled_extension|live|guidance|harness_boundary)",
    re.IGNORECASE,
)

MOCK_NAMES = frozenset({"MagicMock", "Mock", "AsyncMock", "patch", "monkeypatch", "SimpleNamespace"})
MOCK_ATTRS = frozenset({"setattr", "patch", "object"})
ASSERT_CALL_ATTRS = frozenset(
    {
        "assert_called",
        "assert_called_once",
        "assert_called_with",
        "assert_called_once_with",
        "assert_awaited",
        "assert_awaited_once",
        "assert_awaited_with",
        "assert_awaited_once_with",
        "assert_not_called",
        "assert_not_awaited",
        "call_args",
        "call_args_list",
        "call_count",
    }
)


@dataclass(frozen=True)
class AuditCandidate:
    file: str
    lines: int
    test_funcs: int
    commit_count: int
    created_sha: str
    created_date: str
    created_subject: str
    prod_files_changed: int
    prod_churn: int
    test_to_prod_ratio: float
    mock_refs: int
    assert_called_refs: int
    assert_count: int
    private_imports: int
    public_imports: int
    boilerplate_ratio: float
    high_risk: bool
    cases: int | None = None
    unique_lines: int | None = None
    unique_branches: int | None = None
    failures_90d: int | None = None
    duration_s: float | None = None


def _run_git(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def _collect_git_file_origins(repo_root: Path) -> dict[str, dict[str, object]]:
    """Collect commit count and creation metadata for every backend/tests/test_*.py file."""
    output = _run_git(
        repo_root,
        "log",
        "--format=COMMIT\t%H\t%cs\t%s",
        "--name-only",
        "--",
        "backend/tests",
    )
    counts: dict[str, int] = defaultdict(int)
    oldest: dict[str, tuple[str, str, str]] = {}
    current = ("", "", "")
    for line in output.splitlines():
        if line.startswith("COMMIT\t"):
            parts = line.split("\t", 3)
            current = (parts[1], parts[2], parts[3] if len(parts) > 3 else "")
        elif line.startswith("backend/tests/test_") and line.endswith(".py"):
            rel = line[len("backend/") :]
            counts[rel] += 1
            oldest[rel] = current
    return {
        rel: {
            "commit_count": counts[rel],
            "created_sha": oldest[rel][0],
            "created_date": oldest[rel][1],
            "created_subject": oldest[rel][2],
        }
        for rel in counts
    }


def _collect_commit_prod_churn(repo_root: Path, shas: set[str]) -> dict[str, tuple[int, int]]:
    """Return ``sha -> (prod_files_changed, prod_churn_lines)`` for non-test Python files."""
    churn: dict[str, tuple[int, int]] = {}
    for sha in sorted(shas):
        out = _run_git(repo_root, "show", "--numstat", "--format=", sha)
        prod_files = 0
        prod_lines = 0
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) != 3 or parts[0] == "-":
                continue
            added, deleted, path = int(parts[0]), int(parts[1]), parts[2]
            if "/tests/" in path or path.startswith("tests/"):
                continue
            if path.endswith(".py"):
                prod_files += 1
                prod_lines += added + deleted
        churn[sha] = (prod_files, prod_lines)
    return churn


def _analyze_test_ast(path: Path) -> dict[str, object]:
    src = path.read_text(encoding="utf-8", errors="ignore")
    lines = src.count("\n") + 1
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {"lines": lines, "skip": True}

    if "bundled_extension" in src or "pytest.mark.live" in src:
        return {"lines": lines, "skip": True}

    priv_imports = 0
    pub_imports = 0
    mock_refs = 0
    assert_called_refs = 0
    assert_count = 0
    fake_class_lines = 0
    helper_lines = 0
    test_funcs = 0

    for node in tree.body:
        span = (getattr(node, "end_lineno", node.lineno) or node.lineno) - node.lineno + 1
        if isinstance(node, ast.ClassDef) and re.match(r"^_?(Fake|Dummy|Stub|Mock)", node.name):
            fake_class_lines += span
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                test_funcs += 1
            else:
                helper_lines += span

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith(("app.", "deerflow", "scripts.")):
                for alias in node.names:
                    if alias.name.startswith("_") and not alias.name.startswith("__"):
                        priv_imports += 1
                    else:
                        pub_imports += 1
        elif isinstance(node, ast.Assert):
            assert_count += 1
        elif isinstance(node, ast.Name) and node.id in MOCK_NAMES:
            mock_refs += 1
        elif isinstance(node, ast.Attribute):
            if node.attr in MOCK_ATTRS:
                mock_refs += 1
            elif node.attr in ASSERT_CALL_ATTRS:
                assert_called_refs += 1
                assert_count += 1
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "raises":
                assert_count += 1

    return {
        "lines": lines,
        "skip": False,
        "test_funcs": test_funcs,
        "priv_imports": priv_imports,
        "pub_imports": pub_imports,
        "mock_refs": mock_refs,
        "assert_called_refs": assert_called_refs,
        "assert_count": assert_count,
        "boilerplate_ratio": round((fake_class_lines + helper_lines) / max(1, lines), 2),
    }


def _load_coverage_csv(csv_path: Path | None) -> dict[str, dict[str, float | int]]:
    if csv_path is None:
        return {}
    agg: dict[str, dict[str, float | int]] = defaultdict(lambda: {"cases": 0, "unique_lines": 0, "unique_branches": 0, "failures_90d": 0, "duration_s": 0.0})
    with csv_path.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            entry = agg[row["file"]]
            entry["cases"] = int(entry["cases"]) + 1
            entry["unique_lines"] = int(entry["unique_lines"]) + int(row["unique_lines"])
            entry["unique_branches"] = int(entry["unique_branches"]) + int(row["unique_branches"])
            entry["failures_90d"] = int(entry["failures_90d"]) + int(row["failures_90d"])
            entry["duration_s"] = float(entry["duration_s"]) + float(row["duration_s"])
    return dict(agg)


def scan_repository(
    repo_root: Path,
    *,
    coverage_csv: Path | None = None,
    max_commits: int = 2,
    max_prod_files: int = 2,
    max_prod_churn: int = 60,
    min_ratio: float = 4.0,
    min_test_lines: int = 60,
    fix_only: bool = True,
    include_high_risk: bool = False,
) -> list[AuditCandidate]:
    backend_dir = repo_root / "backend"
    origins = _collect_git_file_origins(repo_root)
    cov_map = _load_coverage_csv(coverage_csv)

    pre_filtered: list[tuple[Path, str, dict[str, object]]] = []
    shas_needed: set[str] = set()
    for test_path in sorted((backend_dir / "tests").glob("test_*.py")):
        rel = str(test_path.relative_to(backend_dir))
        if rel.startswith("tests/test_bench_"):
            continue
        origin = origins.get(rel)
        if not origin:
            continue
        if int(origin["commit_count"]) > max_commits:
            continue
        subject = str(origin["created_subject"])
        if fix_only and not subject.lower().startswith("fix"):
            continue
        pre_filtered.append((test_path, rel, origin))
        shas_needed.add(str(origin["created_sha"]))

    churn_by_sha = _collect_commit_prod_churn(repo_root, shas_needed)
    candidates: list[AuditCandidate] = []

    for test_path, rel, origin in pre_filtered:
        sha = str(origin["created_sha"])
        prod_files, prod_churn = churn_by_sha.get(sha, (0, 0))
        if prod_files == 0 or prod_files > max_prod_files or prod_churn == 0 or prod_churn > max_prod_churn:
            continue

        ast_info = _analyze_test_ast(test_path)
        if ast_info.get("skip"):
            continue
        lines = int(ast_info["lines"])
        if lines < min_test_lines:
            continue

        ratio = round(lines / prod_churn, 1)
        if ratio < min_ratio:
            continue

        subject = str(origin["created_subject"])
        high_risk = bool(HIGH_RISK_RE.search(rel) or HIGH_RISK_RE.search(subject))
        if high_risk and not include_high_risk:
            continue

        cov = cov_map.get(rel)
        if cov is not None and int(cov["failures_90d"]) > 0:
            continue

        candidates.append(
            AuditCandidate(
                file=rel,
                lines=lines,
                test_funcs=int(ast_info["test_funcs"]),
                commit_count=int(origin["commit_count"]),
                created_sha=sha[:10],
                created_date=str(origin["created_date"]),
                created_subject=subject,
                prod_files_changed=prod_files,
                prod_churn=prod_churn,
                test_to_prod_ratio=ratio,
                mock_refs=int(ast_info["mock_refs"]),
                assert_called_refs=int(ast_info["assert_called_refs"]),
                assert_count=int(ast_info["assert_count"]),
                private_imports=int(ast_info["priv_imports"]),
                public_imports=int(ast_info["pub_imports"]),
                boilerplate_ratio=float(ast_info["boilerplate_ratio"]),
                high_risk=high_risk,
                cases=int(cov["cases"]) if cov is not None else None,
                unique_lines=int(cov["unique_lines"]) if cov is not None else None,
                unique_branches=int(cov["unique_branches"]) if cov is not None else None,
                failures_90d=int(cov["failures_90d"]) if cov is not None else None,
                duration_s=round(float(cov["duration_s"]), 2) if cov is not None else None,
            )
        )

    candidates.sort(key=lambda item: (-item.test_to_prod_ratio, -item.lines))
    return candidates


def _format_markdown(candidates: list[AuditCandidate], top: int) -> str:
    shown = candidates[:top]
    total_lines = sum(c.lines for c in candidates)
    lines = [
        f"Found **{len(candidates)}** single-PR micro-fix bloated test files (**{total_lines:,}** lines total). Showing top {len(shown)}:",
        "",
        "| # | Test file | Lines | Prod churn | Ratio | Mocks | Priv imports | Commits | Unique cov | Origin commit |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for idx, c in enumerate(shown, 1):
        ucov = "-" if c.unique_lines is None else str(c.unique_lines + (c.unique_branches or 0))
        subject = c.created_subject.replace("|", "\\|")
        if len(subject) > 64:
            subject = subject[:61] + "..."
        lines.append(f"| {idx} | `{c.file}` | {c.lines} | {c.prod_churn}L ({c.prod_files_changed}f) | {c.test_to_prod_ratio:.1f}x | {c.mock_refs} | {c.private_imports} | {c.commit_count} | {ucov} | `{c.created_sha}` {subject} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit single-PR single-spot-defense test bloat.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--coverage-csv", type=Path, default=None, help="Optional per-test coverage/CI CSV")
    parser.add_argument("--max-commits", type=int, default=2)
    parser.add_argument("--max-prod-files", type=int, default=2)
    parser.add_argument("--max-prod-churn", type=int, default=60)
    parser.add_argument("--min-ratio", type=float, default=4.0)
    parser.add_argument("--min-test-lines", type=int, default=60)
    parser.add_argument("--all-prefixes", action="store_true", help="Include feat/refactor PRs, not just fix PRs")
    parser.add_argument("--include-high-risk", action="store_true", help="Include security/concurrency/migration files")
    parser.add_argument("--top", type=int, default=40)
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)

    candidates = scan_repository(
        args.repo_root,
        coverage_csv=args.coverage_csv,
        max_commits=args.max_commits,
        max_prod_files=args.max_prod_files,
        max_prod_churn=args.max_prod_churn,
        min_ratio=args.min_ratio,
        min_test_lines=args.min_test_lines,
        fix_only=not args.all_prefixes,
        include_high_risk=args.include_high_risk,
    )

    if args.format == "json":
        print(json.dumps([asdict(c) for c in candidates[: args.top]], indent=2, ensure_ascii=False))
    else:
        print(_format_markdown(candidates, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
