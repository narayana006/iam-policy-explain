"""Risk checks: wildcards, privilege escalation, public and cross-account access."""

from __future__ import annotations

from dataclasses import dataclass

from .explain import split_operator
from .policy import Policy, Statement

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    statements: list[int]  # 1-based statement numbers, empty for policy-wide

    def at_least(self, threshold: str) -> bool:
        return SEVERITIES.index(self.severity) >= SEVERITIES.index(threshold)


# Publicly documented privilege-escalation techniques: holding every action in
# a set lets a principal obtain permissions beyond what the policy grants.
PRIVESC_PATHS: list[tuple[tuple[str, ...], str]] = [
    (("iam:CreatePolicyVersion",), "publish a new default version of a managed policy with any permissions"),
    (("iam:SetDefaultPolicyVersion",), "switch a managed policy back to an older, more permissive version"),
    (("iam:CreateAccessKey",), "create access keys for another, more privileged user"),
    (("iam:CreateLoginProfile",), "set a console password for a user that has none and sign in as them"),
    (("iam:UpdateLoginProfile",), "reset another user's console password and sign in as them"),
    (("iam:AttachUserPolicy",), "attach any managed policy (e.g. AdministratorAccess) to a user"),
    (("iam:AttachGroupPolicy",), "attach any managed policy to a group"),
    (("iam:AttachRolePolicy",), "attach any managed policy to a role"),
    (("iam:PutUserPolicy",), "write an inline policy with any permissions on a user"),
    (("iam:PutGroupPolicy",), "write an inline policy with any permissions on a group"),
    (("iam:PutRolePolicy",), "write an inline policy with any permissions on a role"),
    (("iam:AddUserToGroup",), "add a user to a more privileged group"),
    (("iam:UpdateAssumeRolePolicy",), "rewrite a role's trust policy so the caller can assume it"),
    (("iam:PassRole", "ec2:RunInstances"), "launch an EC2 instance with a more privileged role and use its credentials"),
    (("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
     "create and invoke a Lambda function that runs as a more privileged role"),
    (("iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"),
     "create a Lambda function with a more privileged role and trigger it from an event source"),
    (("lambda:UpdateFunctionCode",), "replace the code of an existing Lambda function and run as its role"),
    (("iam:PassRole", "glue:CreateDevEndpoint"), "create a Glue dev endpoint with a more privileged role"),
    (("glue:UpdateDevEndpoint",), "add an SSH key to an existing Glue dev endpoint and use its role"),
    (("iam:PassRole", "cloudformation:CreateStack"), "create a CloudFormation stack that acts with a more privileged role"),
    (("iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"),
     "define a Data Pipeline that runs commands with a more privileged role"),
    (("iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"),
     "run an ECS task with a more privileged task role"),
    (("iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"),
     "run a CodeBuild build with a more privileged service role"),
    (("iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"),
     "open a SageMaker notebook that runs with a more privileged role"),
]

# Condition keys that tie a request to a specific caller, account, organization
# or network origin. A positive match on one of these narrows a "*" principal.
_NARROWING_KEYS = {
    "aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn",
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceowner", "aws:sourceorgid",
    "aws:sourcevpc", "aws:sourcevpce", "aws:sourceip", "aws:vpcsourceip", "aws:userid",
    "aws:username", "kms:calleraccount", "s3:dataaccesspointaccount",
}
_READ_ONLY_PREFIXES = ("describe", "list")
_NEGATED = ("stringnot", "arnnot", "notipaddress", "numericnot", "datenot", "null")


def narrowing_keys(statement: Statement) -> list[str]:
    """Condition keys in the statement that positively restrict who may call."""
    found = []
    for operator, block in statement.conditions.items():
        _, base, if_exists = split_operator(operator)
        if if_exists or base.startswith(_NEGATED):
            continue
        found += [key for key in block if key.lower() in _NARROWING_KEYS]
    return found


def _condition_note(statement: Statement) -> str:
    return " (has a Condition, which is not evaluated here)" if statement.conditions else ""


def _only_read_listing(statement: Statement) -> bool:
    if statement.not_action:
        return False
    return all(a.split(":", 1)[-1].lower().startswith(_READ_ONLY_PREFIXES) for a in statement.actions)


def check_wildcards(policy: Policy) -> list[Finding]:
    findings = []
    for s in policy.statements:
        if not s.is_allow:
            continue
        n = [s.index]
        if s.all_actions and s.all_resources:
            if s.conditions:
                findings.append(Finding("high", "ADMIN_CONDITIONAL",
                    f"{s.label} allows every action on every resource, limited only by a Condition "
                    "that is not evaluated here.", n))
            else:
                findings.append(Finding("critical", "ADMIN",
                    f"{s.label} allows every action on every resource: full administrator access.", n))
            continue
        if s.all_actions:
            findings.append(Finding("high", "WILDCARD_ACTION",
                f"{s.label} allows every action (\"*\") on its resources{_condition_note(s)}.", n))
        elif s.not_action:
            findings.append(Finding("high", "ALLOW_NOT_ACTION",
                f"{s.label} uses Allow with NotAction: it allows every action except "
                f"{', '.join(s.actions)} on {'every resource' if s.all_resources else 'its resources'}, "
                f"including actions AWS adds later{_condition_note(s)}.", n))
        else:
            for action in s.actions:
                service, _, name = action.partition(":")
                if name == "*":
                    severity = "high" if service.lower() in ("iam", "sts", "organizations", "kms") else "medium"
                    findings.append(Finding(severity, "WILDCARD_SERVICE",
                        f"{s.label} allows every {service} action (\"{action}\"){_condition_note(s)}.", n))
        if s.not_resource:
            findings.append(Finding("medium", "ALLOW_NOT_RESOURCE",
                f"{s.label} uses Allow with NotResource: it applies to every resource except "
                f"{', '.join(s.resources)}{_condition_note(s)}.", n))
        elif s.all_resources and not s.all_actions and not s.not_action and not _only_read_listing(s):
            findings.append(Finding("medium", "WILDCARD_RESOURCE",
                f"{s.label} applies to every resource (\"*\") for actions that are not only "
                f"Describe*/List*{_condition_note(s)}.", n))
        if (s.covers_action("iam:PassRole") and not s.all_actions and s.all_resources
                and not any(k.lower() == "iam:passedtoservice"
                            for block in s.conditions.values() for k in block)):
            findings.append(Finding("high", "PASSROLE_ANY_ROLE",
                f"{s.label} allows iam:PassRole on every role with no iam:PassedToService condition: "
                "any role in the account can be handed to a service.", n))
    return findings


def _grants(policy: Policy, action: str) -> list[Statement]:
    """Identity-policy Allow statements that grant `action`, unless a blanket Deny blocks it."""
    for s in policy.statements:
        if (not s.is_allow and not s.has_principal and not s.conditions
                and s.all_resources and s.covers_action(action)):
            return []
    return [s for s in policy.statements
            if s.is_allow and not s.has_principal and s.covers_action(action)]


def check_privilege_escalation(policy: Policy) -> list[Finding]:
    open_paths = []
    for actions, effect in PRIVESC_PATHS:
        granted = [_grants(policy, a) for a in actions]
        if all(granted):
            statements = sorted({s.index for group in granted for s in group})
            scoped = all(s.conditions or not s.all_resources for group in granted for s in group)
            open_paths.append((actions, effect, statements, scoped))
    if not open_paths:
        return []
    # A full-admin statement opens every path; one line says that better than 24.
    if any(s.is_allow and s.all_actions and s.all_resources and not s.has_principal
           for s in policy.statements) and len(open_paths) == len(PRIVESC_PATHS):
        return [Finding("high", "PRIVESC",
            f"All {len(PRIVESC_PATHS)} known privilege-escalation paths are open because the policy "
            "allows every action.", sorted({i for p in open_paths for i in p[2]}))]
    findings = []
    for actions, effect, statements, scoped in open_paths:
        # A grant narrowed by resource or Condition may be harmless (e.g. a user
        # managing only their own access keys), so it ranks below an open one.
        note = (" Every grant involved is limited by resource or Condition; check whether "
                "the limit actually prevents this.") if scoped else ""
        where = "statement" + ("s " if len(statements) > 1 else " ") + ", ".join(map(str, statements))
        findings.append(Finding("medium" if scoped else "high", "PRIVESC",
            f"Privilege escalation via {' + '.join(actions)} ({where}): can {effect}.{note}", statements))
    return findings


def check_principals(policy: Policy, own_account: str | None = None) -> list[Finding]:
    findings = []
    for s in policy.statements:
        if not s.is_allow or not s.has_principal:
            continue
        n = [s.index]
        if s.not_principal:
            findings.append(Finding("high", "ALLOW_NOT_PRINCIPAL",
                f"{s.label} uses Allow with NotPrincipal: it grants access to every principal except "
                "the ones listed, including anonymous callers.", n))
            continue
        if any(p.is_anyone for p in s.principals):
            keys = narrowing_keys(s)
            if keys:
                findings.append(Finding("medium", "PUBLIC_WITH_CONDITION",
                    f"{s.label} names anyone (\"*\") as principal, restricted by a condition on "
                    f"{', '.join(keys)}. The condition is not evaluated here; confirm it is tight enough.", n))
            else:
                extra = (" Its Condition does not restrict who the caller is."
                         if s.conditions else "")
                findings.append(Finding("critical", "PUBLIC",
                    f"{s.label} allows anyone (\"*\"), including anonymous callers and every AWS "
                    f"account: public access.{extra}", n))
        accounts = sorted({p.account_id for p in s.principals if p.account_id})
        for account in accounts:
            if own_account is None:
                findings.append(Finding("info", "ACCOUNT_PRINCIPAL",
                    f"{s.label} grants access to principals in account {account}. "
                    "Pass --account <your account id> to classify this as same-account or cross-account.", n))
            elif account != own_account:
                findings.append(Finding("medium", "CROSS_ACCOUNT",
                    f"{s.label} grants access to principals in another account ({account}){_condition_note(s)}.", n))
        if any(p.kind == "Federated" for p in s.principals) and not s.conditions:
            findings.append(Finding("high", "FEDERATED_NO_CONDITION",
                f"{s.label} trusts a federated identity provider with no Condition: every identity "
                "that provider issues can use this statement.", n))
    return findings


def check_version(policy: Policy) -> list[Finding]:
    if policy.version == "2012-10-17":
        return []
    shown = policy.version or "missing"
    return [Finding("low", "OLD_VERSION",
        f"Policy Version is {shown}; only \"2012-10-17\" supports policy variables such as "
        "${aws:username}.", [])]


def run_checks(policy: Policy, own_account: str | None = None) -> list[Finding]:
    findings = (check_wildcards(policy) + check_privilege_escalation(policy)
                + check_principals(policy, own_account) + check_version(policy))
    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.statements or [0], f.code))
    return findings
