"""Command-line interface for iam-policy-explain."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .checks import SEVERITIES, Finding, run_checks
from .evaluate import evaluate
from .explain import describe_policy
from .policy import Policy, PolicyError, load_policy


def _read(path: str) -> tuple[str, str]:
    if path == "-":
        return sys.stdin.read(), "<stdin>"
    with open(path, encoding="utf-8") as handle:
        return handle.read(), path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-policy-explain",
        description="Explain an IAM policy document in plain English and flag risky statements. "
                    "Works offline on JSON files; never calls AWS.",
    )
    parser.add_argument("files", nargs="*", default=["-"], metavar="FILE",
                        help="policy JSON file(s); '-' or nothing reads stdin")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high",
                        help="exit 1 if any finding has this severity or higher (default: high)")
    parser.add_argument("--account", metavar="ID",
                        help="your 12-digit account id, used to tell same-account from cross-account principals")
    parser.add_argument("--can", metavar="ACTION",
                        help="also answer whether the policy allows this action, e.g. s3:GetObject")
    parser.add_argument("--on", metavar="RESOURCE", help="resource ARN for --can")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _render_text(policy: Policy, findings: list[Finding], decision, out) -> None:
    kind = "resource-based policy (has Principal)" if policy.is_resource_policy else "identity-based policy"
    print(f"{policy.source}: {len(policy.statements)} statement(s), {kind}", file=out)
    print(file=out)
    for d in describe_policy(policy):
        title = f"[{d['index']}] {d['effect'].upper()}"
        if d["sid"]:
            title += f"  {d['sid']}"
        print(title, file=out)
        print(f"    who:   {d['who']}", file=out)
        print(f"    what:  {d['what']}", file=out)
        print(f"    where: {d['where']}", file=out)
        for i, cond in enumerate(d["when"]):
            print(f"    {'when:  ' if i == 0 else '  and  '}{cond}", file=out)
    print(file=out)
    if findings:
        print(f"Findings ({len(findings)}):", file=out)
        for f in findings:
            print(f"  {f.severity.upper():<8} {f.code:<22} {f.message}", file=out)
    else:
        print("Findings: none", file=out)
    if decision is not None:
        print(file=out)
        print(f"Check: {decision.result}  {decision.summary}", file=out)
        for m in decision.matches:
            why = "matches" if m.certain else "may match: " + "; ".join(m.reasons)
            print(f"    {m.statement.effect.upper():<5} {m.statement.label}: {why}", file=out)


def _as_json(policy: Policy, findings: list[Finding], decision) -> dict:
    data = {
        "source": policy.source,
        "version": policy.version,
        "resource_policy": policy.is_resource_policy,
        "statements": describe_policy(policy),
        "findings": [vars(f) for f in findings],
    }
    if decision is not None:
        data["check"] = {
            "action": decision.action,
            "resource": decision.resource,
            "result": decision.result,
            "summary": decision.summary,
            "matches": [{"statement": m.statement.index, "effect": m.statement.effect,
                         "certain": m.certain, "reasons": m.reasons} for m in decision.matches],
        }
    return data


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.on and not args.can:
        parser.error("--on requires --can")

    reports = []
    failed = False
    for index, path in enumerate(args.files):
        try:
            text, source = _read(path)
            policy = load_policy(text, source)
        except (OSError, PolicyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        findings = run_checks(policy, args.account)
        decision = evaluate(policy, args.can, args.on) if args.can else None
        if args.fail_on != "never" and any(f.at_least(args.fail_on) for f in findings):
            failed = True
        if args.json:
            reports.append(_as_json(policy, findings, decision))
        else:
            if index:
                print()
            _render_text(policy, findings, decision, sys.stdout)
    if args.json:
        print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
