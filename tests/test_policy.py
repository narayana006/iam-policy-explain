import json

import pytest

from iam_policy_explain.policy import (
    PolicyError, action_matches, has_policy_variable, load_policy, parse_policy, resource_matches,
)


def test_action_matching_is_case_insensitive_with_wildcards():
    assert action_matches("s3:Get*", "s3:getobject")
    assert action_matches("S3:GETOBJECT", "s3:GetObject")
    assert action_matches("*", "iam:PassRole")
    assert action_matches("ec2:Describe?nstances", "ec2:DescribeInstances")
    assert not action_matches("s3:Get*", "s3:PutObject")
    assert not action_matches("s3:Get", "s3:GetObject")


def test_action_pattern_special_characters_are_literal():
    assert not action_matches("s3:Get[O]bject", "s3:GetObject")
    assert not action_matches("s3.GetObject", "s3:GetObject")


def test_resource_matching_is_case_sensitive():
    assert resource_matches("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b.txt")
    assert not resource_matches("arn:aws:s3:::bucket/*", "arn:aws:s3:::Bucket/a")
    assert not resource_matches("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket")
    assert resource_matches("*", "arn:aws:iam::123456789012:role/x")


def test_policy_variables_and_literal_escapes():
    assert has_policy_variable("arn:aws:iam::123456789012:user/${aws:username}")
    assert not has_policy_variable("arn:aws:s3:::bucket/${*}")
    # an unresolved variable could be anything, so it is matched like a wildcard
    assert resource_matches("arn:aws:s3:::b/${aws:username}/*", "arn:aws:s3:::b/alice/x")
    # ${*} is a literal asterisk, not a wildcard
    assert resource_matches("arn:aws:s3:::b/${*}", "arn:aws:s3:::b/*")
    assert not resource_matches("arn:aws:s3:::b/${*}", "arn:aws:s3:::b/key")


def test_single_statement_object_and_string_fields():
    policy = parse_policy({"Version": "2012-10-17",
                           "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}})
    assert len(policy.statements) == 1
    s = policy.statements[0]
    assert s.actions == ["s3:GetObject"] and s.resources == ["*"] and s.all_resources


def test_not_action_and_not_resource_invert_matching():
    policy = parse_policy({"Statement": [{"Effect": "Allow", "NotAction": ["iam:*", "sts:*"],
                                          "NotResource": "arn:aws:s3:::secret/*"}]})
    s = policy.statements[0]
    assert s.covers_action("s3:GetObject")
    assert not s.covers_action("iam:CreateUser")
    assert s.covers_resource("arn:aws:s3:::public/x")
    assert not s.covers_resource("arn:aws:s3:::secret/x")
    assert not s.all_resources and not s.all_actions


def test_principal_forms():
    policy = parse_policy({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"},
        {"Effect": "Allow", "Principal": {"AWS": ["123456789012", "arn:aws:iam::210987654321:role/r"],
                                          "Service": "lambda.amazonaws.com"},
         "Action": "sts:AssumeRole"},
    ]})
    assert policy.statements[0].principals[0].is_anyone
    accounts = [p.account_id for p in policy.statements[1].principals]
    assert accounts == ["123456789012", "210987654321", None]
    assert policy.is_resource_policy


@pytest.mark.parametrize("wrapper", [
    lambda d: {"PolicyVersion": {"Document": d, "VersionId": "v1"}},
    lambda d: {"Policy": json.dumps(d)},
    lambda d: {"Role": {"RoleName": "r", "AssumeRolePolicyDocument": d}},
    lambda d: {"PolicyName": "p", "PolicyDocument": d},
])
def test_aws_cli_output_shapes_are_unwrapped(wrapper):
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    policy = load_policy(json.dumps(wrapper(doc)))
    assert policy.version == "2012-10-17" and len(policy.statements) == 1


@pytest.mark.parametrize("doc, fragment", [
    ({"foo": 1}, "no \"Statement\""),
    ({"Statement": [{"Effect": "Permit", "Action": "*", "Resource": "*"}]}, "Effect"),
    ({"Statement": [{"Effect": "Allow", "Resource": "*"}]}, "Action or NotAction"),
    ({"Statement": [{"Effect": "Allow", "Action": "*", "NotAction": "*"}]}, "Action or NotAction"),
    ({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "NotResource": "*"}]}, "NotResource"),
    ({"Statement": [{"Effect": "Allow", "Action": "*", "Principal": "someone"}]}, "Principal"),
])
def test_invalid_documents_raise(doc, fragment):
    with pytest.raises(PolicyError, match=fragment):
        parse_policy(doc)


def test_invalid_json_raises():
    with pytest.raises(PolicyError, match="not valid JSON"):
        load_policy("{nope")
