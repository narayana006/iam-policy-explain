"""Parse IAM policy JSON into a small model and match actions and resources.

Matching follows the documented IAM rules that can be applied to a policy
document on its own:

* action names are case-insensitive, ``*`` and ``?`` are wildcards;
* resource ARNs are case-sensitive, ``*`` and ``?`` are wildcards;
* ``NotAction`` / ``NotResource`` match everything *except* what they list.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any


class PolicyError(ValueError):
    """The input is not a usable IAM policy document."""


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


# ${*}, ${?} and ${$} are IAM's escapes for a literal character. Any other
# ${...} is a policy variable whose value is only known at request time.
_VARIABLE = re.compile(r"\$\{([^}]*)\}")


def has_policy_variable(pattern: str) -> bool:
    return any(m.group(1) not in ("*", "?", "$") for m in _VARIABLE.finditer(pattern))


@lru_cache(maxsize=4096)
def _glob_regex(pattern: str, ignore_case: bool) -> re.Pattern:
    out = []
    pos = 0
    for m in _VARIABLE.finditer(pattern):
        out.append(_glob_chunk(pattern[pos:m.start()]))
        inner = m.group(1)
        # literal escapes stay literal; a real variable could be anything
        out.append(re.escape(inner) if inner in ("*", "?", "$") else ".*")
        pos = m.end()
    out.append(_glob_chunk(pattern[pos:]))
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL if ignore_case else re.DOTALL)


def _glob_chunk(text: str) -> str:
    return "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in text)


def action_matches(pattern: str, action: str) -> bool:
    """True if the action pattern from a policy covers a concrete action name."""
    return _glob_regex(pattern, True).fullmatch(action) is not None


def resource_matches(pattern: str, resource: str) -> bool:
    """True if the resource pattern from a policy covers a concrete ARN."""
    return _glob_regex(pattern, False).fullmatch(resource) is not None


@dataclass
class Principal:
    kind: str  # "*", "AWS", "Service", "Federated", "CanonicalUser"
    value: str

    @property
    def is_anyone(self) -> bool:
        return self.value == "*" and self.kind in ("*", "AWS")

    @property
    def account_id(self) -> str | None:
        if self.kind != "AWS":
            return None
        if re.fullmatch(r"\d{12}", self.value):
            return self.value
        m = re.match(r"arn:[^:]*:(?:iam|sts)::(\d{12}):", self.value)
        return m.group(1) if m else None

    def __str__(self) -> str:
        return "anyone (*)" if self.is_anyone else f"{self.kind}: {self.value}"


@dataclass
class Statement:
    index: int  # 1-based position in the policy
    sid: str | None
    effect: str  # "Allow" or "Deny"
    actions: list[str]
    not_action: bool
    resources: list[str]
    not_resource: bool
    principals: list[Principal]
    not_principal: bool
    conditions: dict[str, dict[str, list[str]]] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"statement {self.index}" + (f" ({self.sid})" if self.sid else "")

    @property
    def is_allow(self) -> bool:
        return self.effect == "Allow"

    @property
    def has_principal(self) -> bool:
        return bool(self.principals)

    def covers_action(self, action: str) -> bool:
        hit = any(action_matches(p, action) for p in self.actions)
        return not hit if self.not_action else hit

    def covers_resource(self, resource: str) -> bool:
        if not self.resources:  # e.g. a role trust policy: the role itself
            return True
        hit = any(resource_matches(p, resource) for p in self.resources)
        return not hit if self.not_resource else hit

    @property
    def all_actions(self) -> bool:
        return not self.not_action and "*" in self.actions

    @property
    def all_resources(self) -> bool:
        """True when the statement applies to every resource."""
        if not self.resources:
            return False
        return not self.not_resource and "*" in self.resources

    @property
    def uses_policy_variables(self) -> bool:
        return any(has_policy_variable(r) for r in self.resources)


@dataclass
class Policy:
    version: str | None
    statements: list[Statement]
    source: str = "<policy>"

    @property
    def is_resource_policy(self) -> bool:
        return any(s.has_principal for s in self.statements)


def _unwrap(doc: Any) -> Any:
    """Accept common AWS CLI output shapes as well as a bare policy document."""
    for _ in range(4):
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError as exc:
                raise PolicyError(f"embedded policy string is not JSON: {exc}") from exc
            continue
        if not isinstance(doc, dict) or "Statement" in doc:
            return doc
        for path in (
            ("PolicyVersion", "Document"),     # aws iam get-policy-version
            ("Role", "AssumeRolePolicyDocument"),  # aws iam get-role
            ("PolicyDocument",),               # get-role-policy / get-user-policy
            ("AssumeRolePolicyDocument",),
            ("Document",),
            ("Policy",),                       # aws s3api get-bucket-policy (string)
        ):
            node = doc
            for key in path:
                node = node.get(key) if isinstance(node, dict) else None
            if node is not None:
                doc = node
                break
        else:
            return doc
    return doc


def _parse_principals(raw: Any, where: str) -> list[Principal]:
    if raw is None:
        return []
    if raw == "*":
        return [Principal("*", "*")]
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: Principal must be \"*\" or an object")
    out = []
    for kind, values in raw.items():
        for value in _as_list(values):
            out.append(Principal(kind, str(value)))
    return out


def _parse_conditions(raw: Any, where: str) -> dict[str, dict[str, list[str]]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: Condition must be an object")
    out: dict[str, dict[str, list[str]]] = {}
    for operator, block in raw.items():
        if not isinstance(block, dict):
            raise PolicyError(f"{where}: Condition operator {operator} must map keys to values")
        out[operator] = {
            key: [str(v).lower() if isinstance(v, bool) else str(v) for v in _as_list(values)]
            for key, values in block.items()
        }
    return out


def parse_policy(doc: Any, source: str = "<policy>") -> Policy:
    doc = _unwrap(doc)
    if not isinstance(doc, dict) or "Statement" not in doc:
        raise PolicyError(f"{source}: no \"Statement\" element found; is this an IAM policy?")
    raw_statements = doc["Statement"]
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        raise PolicyError(f"{source}: \"Statement\" must be an object or a list")

    statements = []
    for i, raw in enumerate(raw_statements, start=1):
        where = f"{source}: statement {i}"
        if not isinstance(raw, dict):
            raise PolicyError(f"{where}: must be an object")
        effect = raw.get("Effect")
        if effect not in ("Allow", "Deny"):
            raise PolicyError(f"{where}: Effect must be \"Allow\" or \"Deny\", got {effect!r}")
        if ("Action" in raw) == ("NotAction" in raw):
            raise PolicyError(f"{where}: needs exactly one of Action or NotAction")
        if "Resource" in raw and "NotResource" in raw:
            raise PolicyError(f"{where}: has both Resource and NotResource")
        if "Principal" in raw and "NotPrincipal" in raw:
            raise PolicyError(f"{where}: has both Principal and NotPrincipal")
        not_action = "NotAction" in raw
        not_resource = "NotResource" in raw
        not_principal = "NotPrincipal" in raw
        statements.append(
            Statement(
                index=i,
                sid=raw.get("Sid"),
                effect=effect,
                actions=[str(a) for a in _as_list(raw["NotAction" if not_action else "Action"])],
                not_action=not_action,
                resources=[str(r) for r in _as_list(raw.get("NotResource" if not_resource else "Resource"))],
                not_resource=not_resource,
                principals=_parse_principals(
                    raw.get("NotPrincipal" if not_principal else "Principal"), where
                ),
                not_principal=not_principal,
                conditions=_parse_conditions(raw.get("Condition"), where),
            )
        )
    version = doc.get("Version")
    return Policy(version=str(version) if version is not None else None,
                  statements=statements, source=source)


def load_policy(text: str, source: str = "<policy>") -> Policy:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{source}: not valid JSON ({exc})") from exc
    return parse_policy(doc, source)
