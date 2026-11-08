#!/usr/bin/env python3
"""Security autopatch helper, used by .github/workflows/security-autopatch.yml.

`audit` mode runs pip-audit against the requirements file. For every
dependency whose resolved version has a known vulnerability with a
published fix, it raises that dependency's version range in place so a
fresh install resolves to a fixed version. It writes a JSON summary:

    {
      "changed": bool,          # the requirements file was rewritten
      "packages": {name: {"old": line, "new": spec, "advisories": [ids]}},
      "unfixable": [{"package": ..., "id": ..., "note": ...}]
    }

`notes` mode renders release notes markdown from that summary for the
automated release.

Exit code is 0 unless the tool itself fails; outcomes are communicated
through the summary file so the workflow can branch on them.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from packaging.version import InvalidVersion, Version


def run_pip_audit(requirements: Path) -> dict:
    proc = subprocess.run(
        [
            sys.executable, "-m", "pip_audit",
            "-r", str(requirements),
            "-f", "json",
            "--progress-spinner", "off",
        ],
        capture_output=True,
        text=True,
    )
    # pip-audit exits 0 when clean and 1 when vulnerabilities are found;
    # anything else (or unparseable output) is an operational error.
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(proc.stdout, file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"pip-audit failed (exit {proc.returncode})")


def ceiling_for(version: Version) -> str:
    """Upper bound two majors above the fix, matching the existing
    `>=49.0.0,<51.0.0` style of requirements.txt."""
    return f"{version.major + 2}.0.0"


def audit(args: argparse.Namespace) -> int:
    req_path = Path(args.requirements)
    report = run_pip_audit(req_path)

    needed: dict[str, dict] = {}
    unfixable: list[dict] = []
    for dep in report.get("dependencies", []):
        name = dep.get("name", "")
        for vuln in dep.get("vulns") or []:
            fixes = []
            for fv in vuln.get("fix_versions") or []:
                try:
                    fixes.append(Version(fv))
                except InvalidVersion:
                    continue
            if not fixes:
                unfixable.append({
                    "package": name,
                    "id": vuln.get("id", "unknown"),
                    "note": "no published fix version",
                })
                continue
            fix = min(fixes)  # smallest version that resolves this advisory
            entry = needed.setdefault(name, {"fix": fix, "advisories": []})
            entry["advisories"].append(vuln.get("id", "unknown"))
            if fix > entry["fix"]:
                entry["fix"] = fix

    text = req_path.read_text()
    packages: dict[str, dict] = {}
    for name, entry in sorted(needed.items()):
        pattern = re.compile(
            rf"^{re.escape(name)}\s*(?:[<>=!~;\[][^#\n]*)?$",
            re.IGNORECASE | re.MULTILINE,
        )
        match = pattern.search(text)
        new_spec = f"{name}>={entry['fix']},<{ceiling_for(entry['fix'])}"
        if match is None:
            unfixable.append({
                "package": name,
                "id": ", ".join(entry["advisories"]),
                "note": "not listed in requirements file (transitive dependency); needs a manual decision",
            })
            continue
        packages[name] = {
            "old": match.group(0).strip(),
            "new": new_spec,
            "advisories": sorted(set(entry["advisories"])),
        }
        text = text[: match.start()] + new_spec + text[match.end():]

    changed = bool(packages)
    if changed:
        req_path.write_text(text)

    summary = {"changed": changed, "packages": packages, "unfixable": unfixable}
    Path(args.summary).write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


def notes(args: argparse.Namespace) -> int:
    summary = json.loads(Path(args.summary).read_text())
    lines = [
        f"# OCSP Server Test Suite {args.version}",
        "",
        "Automated security release. A published vulnerability in a dependency",
        "has a fix available outside the previously allowed version range, so",
        "this release raises the range; a fresh install now resolves to a",
        "patched library. No application code was changed.",
        "",
        "## Dependency updates",
        "",
    ]
    for name, info in sorted(summary.get("packages", {}).items()):
        advisories = ", ".join(info["advisories"])
        lines.append(f"- **{name}**: `{info['old']}` → `{info['new']}` (addresses: {advisories})")
    lines += [
        "",
        "## Upgrading an existing install",
        "",
        "```bash",
        "git pull            # or download the new ZIP",
        "pip install -r requirements.txt --upgrade",
        "```",
        "",
        "Published automatically by the security-autopatch workflow after the",
        "full check suite (smoke test and re-audit) passed on the updated",
        "requirements.",
        "",
    ]
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    print(f"wrote {out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="audit and rewrite requirement ranges")
    p_audit.add_argument("--requirements", default="requirements.txt")
    p_audit.add_argument("--summary", default="autopatch-summary.json")
    p_audit.set_defaults(func=audit)

    p_notes = sub.add_parser("notes", help="render release notes from a summary")
    p_notes.add_argument("--summary", default="autopatch-summary.json")
    p_notes.add_argument("--version", required=True)
    p_notes.add_argument("--output", required=True)
    p_notes.set_defaults(func=notes)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
