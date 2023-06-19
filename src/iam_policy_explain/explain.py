"""Turn parsed statements into plain-English descriptions."""

from __future__ import annotations

from .policy import Policy, Statement

# operator -> (phrase, negated)
_OPERATORS = {
    "stringequals": ("equals", False),
    "stringnotequals": ("does not equal", True),
    "stringequalsignorecase": ("equals (ignoring case)", False),
    "stringnotequalsignorecase": ("does not equal (ignoring case)", True),
    "stringlike": ("matches", False),
    "stringnotlike": ("does not match", True),
    "numericequals": ("=", False),
    "numericnotequals": ("!=", True),
    "numericlessthan": ("<", False),
    "numericlessthanequals": ("<=", False),
    "numericgreaterthan": (">", False),
    "numericgreaterthanequals": (">=", False),
    "dateequals": ("is exactly", False),
    "datenotequals": ("is not", True),
    "datelessthan": ("is before", False),
    "datelessthanequals": ("is at or before", False),
    "dategreaterthan": ("is after", False),
    "dategreaterthanequals": ("is at or after", False),
    "bool": ("is", False),
    "binaryequals": ("equals (binary)", False),
    "ipaddress": ("is in", False),
    "notipaddress": ("is not in", True),
    "arnequals": ("matches ARN", False),
    "arnlike": ("matches ARN", False),
    "arnnotequals": ("does not match ARN", True),
    "arnnotlike": ("does not match ARN", True),
}


def split_operator(operator: str) -> tuple[str, str, bool]:
    """Return (set qualifier, base operator lower-cased, has IfExists)."""
    qualifier = ""
    base = operator
    if ":" in operator:
        qualifier, base = operator.split(":", 1)
    if_exists = base.lower().endswith("ifexists")
    if if_exists:
        base = base[: -len("IfExists")]
    return qualifier.lower(), base.lower(), if_exists


def describe_condition(operator: str, key: str, values: list[str]) -> str:
    qualifier, base, if_exists = split_operator(operator)
    subject = key
    if qualifier == "forallvalues":
        subject = f"every value of {key}"
    elif qualifier == "foranyvalue":
        subject = f"at least one value of {key}"

    if base == "null":
        wants_absent = [v.lower() == "true" for v in values]
        text = f"{key} is absent" if all(wants_absent) else f"{key} is present"
    elif base in _OPERATORS:
        phrase, negated = _OPERATORS[base]
        joined = (" and " if negated else " or ").join(values) if values else "(no values)"
        text = f"{subject} {phrase} {joined}"
    else:
        text = f"{subject} {operator} {', '.join(values)}"
    if if_exists:
        text += " (or the key is absent)"
    return text


def describe_conditions(statement: Statement) -> list[str]:
    return [
        describe_condition(operator, key, values)
        for operator, block in statement.conditions.items()
        for key, values in block.items()
    ]


def _who(statement: Statement) -> str:
    if not statement.principals:
        return "the identity this policy is attached to"
    names = ", ".join(str(p) for p in statement.principals)
    if statement.not_principal:
        return f"everyone EXCEPT {names}"
    return names


def _what(statement: Statement) -> str:
    if statement.not_action:
        return "every action EXCEPT " + ", ".join(statement.actions)
    if statement.all_actions:
        return "every action in every service (*)"
    return ", ".join(statement.actions)


def _where(statement: Statement) -> str:
    if not statement.resources:
        return "the resource this policy is attached to"
    if statement.not_resource:
        return "every resource EXCEPT " + ", ".join(statement.resources)
    if statement.all_resources:
        return "every resource (*)"
    return ", ".join(statement.resources)


def describe_statement(statement: Statement) -> dict:
    return {
        "index": statement.index,
        "sid": statement.sid,
        "effect": statement.effect,
        "who": _who(statement),
        "what": _what(statement),
        "where": _where(statement),
        "when": describe_conditions(statement),
    }


def sentence(statement: Statement) -> str:
    d = describe_statement(statement)
    verb = "ALLOWS" if statement.is_allow else "DENIES"
    text = f"{verb} {d['what']} on {d['where']} for {d['who']}"
    if d["when"]:
        text += ", only when " + " AND ".join(d["when"])
    return text + "."


def describe_policy(policy: Policy) -> list[dict]:
    return [{**describe_statement(s), "summary": sentence(s)} for s in policy.statements]
