"""Answer "does this one policy allow ACTION on RESOURCE?".

This is deliberately a single-document check. It applies the parts of IAM
policy evaluation that can be decided from the document alone:

* an explicit Deny that matches always wins over any Allow;
* without a matching Allow the answer is an implicit deny;
* Condition blocks and policy variables are NOT evaluated, so a statement
  that depends on them is reported as "conditional" instead of guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .policy import Policy, Statement

EXPLICIT_DENY = "EXPLICIT_DENY"
ALLOWED = "ALLOWED"
CONDITIONAL = "CONDITIONAL"
IMPLICIT_DENY = "IMPLICIT_DENY"


@dataclass
class Match:
    statement: Statement
    certain: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class Decision:
    action: str
    resource: str | None
    result: str
    summary: str
    matches: list[Match]


def _match(statement: Statement, action: str, resource: str | None) -> Match | None:
    if not statement.covers_action(action):
        return None
    reasons: list[str] = []
    if resource is None:
        if statement.resources and not statement.all_resources:
            reasons.append("no resource given and the statement is limited to specific resources")
    else:
        if not statement.covers_resource(resource):
            return None
        if statement.uses_policy_variables:
            reasons.append("the resource uses a policy variable (${...}) that is not resolved")
    if statement.conditions:
        reasons.append("it has a Condition block, which is not evaluated")
    if statement.not_principal:
        reasons.append("it uses NotPrincipal, which is not evaluated")
    elif statement.principals and not all(p.is_anyone for p in statement.principals):
        reasons.append("it applies only to the listed principals, which are not evaluated")
    return Match(statement, certain=not reasons, reasons=reasons)


def evaluate(policy: Policy, action: str, resource: str | None = None) -> Decision:
    matches = [m for s in policy.statements if (m := _match(s, action, resource))]
    denies = [m for m in matches if not m.statement.is_allow]
    allows = [m for m in matches if m.statement.is_allow]
    target = f"{action} on {resource}" if resource else action

    if any(m.certain for m in denies):
        winner = next(m for m in denies if m.certain)
        result = EXPLICIT_DENY
        summary = f"{target} is explicitly denied by {winner.statement.label}; an explicit deny overrides every allow."
    elif not allows:
        result = IMPLICIT_DENY
        summary = f"{target} is not allowed by this policy (implicit deny: no Allow statement matches)."
    elif denies:
        result = CONDITIONAL
        summary = (f"{target} matches an Allow, but {denies[0].statement.label} may deny it "
                   "depending on things this tool does not evaluate.")
    elif any(m.certain for m in allows):
        winner = next(m for m in allows if m.certain)
        result = ALLOWED
        summary = f"{target} is allowed by {winner.statement.label} and no Deny statement matches."
    else:
        result = CONDITIONAL
        summary = (f"{target} is allowed by {allows[0].statement.label} only if conditions "
                   "this tool does not evaluate are met.")
    return Decision(action, resource, result, summary, matches)
