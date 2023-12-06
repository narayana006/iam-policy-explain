from iam_policy_explain.evaluate import ALLOWED, CONDITIONAL, EXPLICIT_DENY, IMPLICIT_DENY, evaluate
from iam_policy_explain.policy import parse_policy

BUCKET = "arn:aws:s3:::data"
KEY = "arn:aws:s3:::data/reports/q1.csv"


def decide(statements, action, resource=None):
    return evaluate(parse_policy({"Version": "2012-10-17", "Statement": statements}), action, resource).result


def test_allow_and_implicit_deny():
    stmts = [{"Effect": "Allow", "Action": "s3:Get*", "Resource": BUCKET + "/*"}]
    assert decide(stmts, "s3:GetObject", KEY) == ALLOWED
    assert decide(stmts, "s3:PutObject", KEY) == IMPLICIT_DENY
    assert decide(stmts, "s3:GetObject", "arn:aws:s3:::other/x") == IMPLICIT_DENY
    assert decide([], "s3:GetObject", KEY) == IMPLICIT_DENY


def test_explicit_deny_beats_allow_regardless_of_order():
    allow = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    deny = {"Effect": "Deny", "Action": "s3:Delete*", "Resource": BUCKET + "/*"}
    for stmts in ([allow, deny], [deny, allow]):
        assert decide(stmts, "s3:DeleteObject", KEY) == EXPLICIT_DENY
        assert decide(stmts, "s3:GetObject", KEY) == ALLOWED


def test_deny_with_not_action_denies_everything_else():
    stmts = [{"Effect": "Allow", "Action": "*", "Resource": "*"},
             {"Effect": "Deny", "NotAction": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}]
    assert decide(stmts, "s3:GetObject", KEY) == ALLOWED
    assert decide(stmts, "ec2:TerminateInstances", "arn:aws:ec2:us-east-1:123456789012:instance/i-0") == EXPLICIT_DENY


def test_allow_with_not_action_does_not_deny_listed_actions():
    # NotAction in an Allow leaves the listed actions un-granted, not denied.
    stmts = [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]
    assert decide(stmts, "iam:CreateUser", "arn:aws:iam::123456789012:user/x") == IMPLICIT_DENY
    stmts.append({"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"})
    assert decide(stmts, "iam:CreateUser", "arn:aws:iam::123456789012:user/x") == ALLOWED


def test_not_resource():
    stmts = [{"Effect": "Allow", "Action": "s3:*", "NotResource": "arn:aws:s3:::secret/*"}]
    assert decide(stmts, "s3:GetObject", KEY) == ALLOWED
    assert decide(stmts, "s3:GetObject", "arn:aws:s3:::secret/k") == IMPLICIT_DENY


def test_conditional_allow_is_not_reported_as_allowed():
    stmts = [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
              "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}]
    assert decide(stmts, "s3:GetObject", KEY) == CONDITIONAL


def test_conditional_deny_makes_an_allow_conditional():
    stmts = [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
             {"Effect": "Deny", "Action": "s3:*", "Resource": "*",
              "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]
    assert decide(stmts, "s3:GetObject", KEY) == CONDITIONAL


def test_conditional_deny_without_any_allow_is_still_implicit_deny():
    stmts = [{"Effect": "Deny", "Action": "s3:*", "Resource": "*",
              "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]
    assert decide(stmts, "s3:GetObject", KEY) == IMPLICIT_DENY


def test_unconditional_deny_wins_over_conditional_deny_and_allow():
    stmts = [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
             {"Effect": "Deny", "Action": "s3:*", "Resource": "*",
              "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
             {"Effect": "Deny", "Action": "s3:GetObject", "Resource": KEY}]
    assert decide(stmts, "s3:GetObject", KEY) == EXPLICIT_DENY


def test_policy_variable_in_resource_is_conditional():
    stmts = [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/${aws:username}/*"}]
    assert decide(stmts, "s3:GetObject", "arn:aws:s3:::data/alice/x") == CONDITIONAL
    assert decide(stmts, "s3:GetObject", "arn:aws:s3:::other/alice/x") == IMPLICIT_DENY


def test_without_resource_only_star_statements_are_certain():
    scoped = [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": BUCKET + "/*"}]
    assert decide(scoped, "s3:GetObject") == CONDITIONAL
    assert decide([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}], "s3:GetObject") == ALLOWED
    assert decide(scoped + [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}], "s3:GetObject") == EXPLICIT_DENY


def test_resource_policy_principals_are_not_evaluated():
    named = [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::210987654321:root"},
              "Action": "s3:GetObject", "Resource": BUCKET + "/*"}]
    assert decide(named, "s3:GetObject", KEY) == CONDITIONAL
    public = [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": BUCKET + "/*"}]
    assert decide(public, "s3:GetObject", KEY) == ALLOWED


def test_trust_policy_without_resource_element():
    stmts = [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
    assert decide(stmts, "sts:AssumeRole", "arn:aws:iam::123456789012:role/r") == ALLOWED


def test_summary_names_the_deciding_statement():
    policy = parse_policy({"Statement": [
        {"Sid": "A", "Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Sid": "NoDelete", "Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]})
    decision = evaluate(policy, "s3:deletebucket", BUCKET)
    assert "statement 2 (NoDelete)" in decision.summary and len(decision.matches) == 2
