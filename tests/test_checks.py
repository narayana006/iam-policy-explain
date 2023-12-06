from iam_policy_explain.checks import PRIVESC_PATHS, run_checks
from iam_policy_explain.policy import parse_policy


def findings(statements, account=None, version="2012-10-17"):
    doc = {"Statement": statements}
    if version:
        doc["Version"] = version
    return run_checks(parse_policy(doc), account)


def codes(statements, **kw):
    return [(f.severity, f.code) for f in findings(statements, **kw)]


def test_full_admin_is_critical_and_collapses_privesc():
    result = findings([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    assert [(f.severity, f.code) for f in result] == [("critical", "ADMIN"), ("high", "PRIVESC")]
    assert str(len(PRIVESC_PATHS)) in result[1].message


def test_admin_with_condition_is_high_not_critical():
    result = codes([{"Effect": "Allow", "Action": "*", "Resource": "*",
                     "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}])
    assert ("high", "ADMIN_CONDITIONAL") in result
    assert ("critical", "ADMIN") not in result


def test_deny_statements_are_never_flagged_for_wildcards():
    assert codes([{"Effect": "Deny", "Action": "*", "Resource": "*"}]) == []


def test_service_wildcard_severity_depends_on_service():
    assert ("medium", "WILDCARD_SERVICE") in codes(
        [{"Effect": "Allow", "Action": "sqs:*", "Resource": "arn:aws:sqs:us-east-1:123456789012:q"}])
    assert ("high", "WILDCARD_SERVICE") in codes(
        [{"Effect": "Allow", "Action": "IAM:*", "Resource": "arn:aws:iam::123456789012:role/app-*"}])


def test_wildcard_resource_ignored_for_describe_and_list_only():
    assert codes([{"Effect": "Allow", "Action": ["ec2:Describe*", "s3:ListAllMyBuckets"], "Resource": "*"}]) == []
    assert ("medium", "WILDCARD_RESOURCE") in codes(
        [{"Effect": "Allow", "Action": ["ec2:Describe*", "s3:GetObject"], "Resource": "*"}])


def test_allow_with_not_action_and_not_resource():
    result = codes([{"Effect": "Allow", "NotAction": "iam:*", "NotResource": "arn:aws:s3:::secret/*"}])
    assert ("high", "ALLOW_NOT_ACTION") in result
    assert ("medium", "ALLOW_NOT_RESOURCE") in result


def test_not_action_allow_opens_privesc_for_unlisted_actions():
    result = findings([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
    messages = [f.message for f in result if f.code == "PRIVESC"]
    assert any("lambda:UpdateFunctionCode" in m for m in messages)
    assert not any("iam:CreatePolicyVersion" in m for m in messages)


def test_privesc_combination_across_statements():
    result = findings([
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
        {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
    ])
    hit = [f for f in result if f.code == "PRIVESC"]
    assert len(hit) == 1 and hit[0].severity == "high" and hit[0].statements == [1, 2]
    assert ("high", "PASSROLE_ANY_ROLE") in [(f.severity, f.code) for f in result]


def test_privesc_needs_every_action_of_the_combination():
    assert "PRIVESC" not in [c for _, c in codes(
        [{"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}])]


def test_privesc_matches_wildcard_patterns_case_insensitively():
    result = findings([{"Effect": "Allow", "Action": "iam:createpolicyv*", "Resource": "*"}])
    assert any(f.code == "PRIVESC" and "iam:CreatePolicyVersion" in f.message for f in result)


def test_blanket_deny_removes_privesc_but_scoped_deny_does_not():
    allow = {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
    blanket = codes([allow, {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}])
    assert "PRIVESC" not in [c for _, c in blanket]
    scoped = codes([allow, {"Effect": "Deny", "Action": "iam:*", "Resource": "arn:aws:iam::123456789012:role/admin"}])
    assert "PRIVESC" in [c for _, c in scoped]
    conditional = codes([allow, {"Effect": "Deny", "Action": "iam:*", "Resource": "*",
                                 "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}}])
    assert "PRIVESC" in [c for _, c in conditional]


def test_resource_scoped_privesc_is_medium():
    result = findings([{"Effect": "Allow", "Action": "iam:CreateAccessKey",
                        "Resource": "arn:aws:iam::123456789012:user/${aws:username}"}])
    assert [(f.severity, f.code) for f in result] == [("medium", "PRIVESC")]


def test_passrole_with_passed_to_service_condition_is_not_flagged_as_any_role():
    result = codes([{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
                     "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}}])
    assert "PASSROLE_ANY_ROLE" not in [c for _, c in result]


def test_public_principal_forms():
    for principal in ("*", {"AWS": "*"}, {"AWS": ["*"]}):
        assert ("critical", "PUBLIC") in codes(
            [{"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::b/*"}])


def test_public_principal_narrowed_by_org_condition_is_medium():
    result = codes([{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                     "Resource": "arn:aws:s3:::b/*",
                     "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}}])
    assert result == [("medium", "PUBLIC_WITH_CONDITION")]


def test_public_principal_with_unrelated_or_negated_condition_stays_critical():
    for condition in (
        {"Bool": {"aws:SecureTransport": "true"}},
        {"StringNotEquals": {"aws:PrincipalAccount": "123456789012"}},
        {"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-exampleorgid"}},
    ):
        assert ("critical", "PUBLIC") in codes(
            [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
              "Resource": "arn:aws:s3:::b/*", "Condition": condition}])


def test_public_deny_is_not_a_finding():
    assert codes([{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*",
                   "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]) == []


def test_cross_account_classification_needs_own_account():
    stmt = [{"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::210987654321:root", "123456789012"]},
             "Action": "sts:AssumeRole"}]
    assert codes(stmt) == [("info", "ACCOUNT_PRINCIPAL"), ("info", "ACCOUNT_PRINCIPAL")]
    assert codes(stmt, account="123456789012") == [("medium", "CROSS_ACCOUNT")]
    assert "210987654321" in findings(stmt, account="123456789012")[0].message


def test_service_principal_is_not_cross_account():
    assert codes([{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}], account="123456789012") == []


def test_allow_not_principal_and_federated_without_condition():
    assert ("high", "ALLOW_NOT_PRINCIPAL") in codes(
        [{"Effect": "Allow", "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:user/x"},
          "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}])
    fed = {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}
    assert ("high", "FEDERATED_NO_CONDITION") in codes(
        [{"Effect": "Allow", "Principal": fed, "Action": "sts:AssumeRoleWithWebIdentity"}])
    assert codes([{"Effect": "Allow", "Principal": fed, "Action": "sts:AssumeRoleWithWebIdentity",
                   "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:o/r:*"}}}]) == []


def test_old_or_missing_version_is_low():
    stmt = [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::b"}]
    assert codes(stmt, version=None) == [("low", "OLD_VERSION")]
    assert codes(stmt, version="2008-10-17") == [("low", "OLD_VERSION")]
    assert codes(stmt) == []
