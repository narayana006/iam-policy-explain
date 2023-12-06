import io
import json
from pathlib import Path

import pytest

from iam_policy_explain.cli import main
from iam_policy_explain.explain import describe_condition, sentence
from iam_policy_explain.policy import parse_policy

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_risky_example_fails_with_default_threshold(capsys):
    code, out, _ = run(capsys, str(EXAMPLES / "developer-policy.json"))
    assert code == 1
    assert "PASSROLE_ANY_ROLE" in out and "iam:PassRole + ec2:RunInstances" in out
    assert "aws:SourceIp is in 203.0.113.0/24 or 198.51.100.0/24" in out


def test_clean_example_passes(capsys):
    code, out, _ = run(capsys, str(EXAMPLES / "read-only.json"))
    assert code == 0 and "Findings: none" in out


def test_fail_on_thresholds(capsys):
    trust = str(EXAMPLES / "trust-policy.json")
    assert run(capsys, trust, "--account", "123456789012")[0] == 0
    assert run(capsys, trust, "--account", "123456789012", "--fail-on", "medium")[0] == 1
    assert run(capsys, str(EXAMPLES / "bucket-policy.json"), "--fail-on", "never")[0] == 0


def test_json_output_and_check(capsys):
    code, out, _ = run(capsys, str(EXAMPLES / "bucket-policy.json"), "--json", "--account", "123456789012",
                       "--can", "s3:GetObject", "--on", "arn:aws:s3:::example-site-assets/public/logo.png")
    data = json.loads(out)
    assert code == 1
    assert data["resource_policy"] is True
    assert {f["code"] for f in data["findings"]} == {"PUBLIC", "CROSS_ACCOUNT", "PUBLIC_WITH_CONDITION"}
    # allowed by the public statement, but the conditional Deny on insecure transport may apply
    assert data["check"]["result"] == "CONDITIONAL"
    assert [m["statement"] for m in data["check"]["matches"]] == [1, 4]


def test_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO((EXAMPLES / "read-only.json").read_text()))
    code, out, _ = run(capsys)
    assert code == 0 and out.startswith("<stdin>: 2 statement(s)")


def test_multiple_files_json_is_a_list(capsys):
    code, out, _ = run(capsys, str(EXAMPLES / "read-only.json"), str(EXAMPLES / "trust-policy.json"), "--json")
    assert code == 0 and len(json.loads(out)) == 2


def test_errors_exit_2(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    code, _, err = run(capsys, str(bad))
    assert code == 2 and "not valid JSON" in err
    code, _, err = run(capsys, str(tmp_path / "missing.json"))
    assert code == 2 and "error:" in err
    with pytest.raises(SystemExit) as exc:
        main([str(bad), "--on", "arn:aws:s3:::b"])
    assert exc.value.code == 2


def test_condition_phrasing():
    assert describe_condition("StringNotEquals", "aws:RequestedRegion", ["eu-west-1", "eu-central-1"]) == \
        "aws:RequestedRegion does not equal eu-west-1 and eu-central-1"
    assert describe_condition("Null", "aws:MultiFactorAuthAge", ["true"]) == "aws:MultiFactorAuthAge is absent"
    assert describe_condition("ForAllValues:StringLike", "aws:TagKeys", ["team-*"]) == \
        "every value of aws:TagKeys matches team-*"
    assert describe_condition("BoolIfExists", "aws:MultiFactorAuthPresent", ["false"]) == \
        "aws:MultiFactorAuthPresent is false (or the key is absent)"
    assert describe_condition("MadeUpOperator", "k", ["v"]) == "k MadeUpOperator v"


def test_sentence_for_deny_with_not_action():
    policy = parse_policy({"Statement": [{"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*",
                                          "Condition": {"Bool": {"aws:SecureTransport": False}}}]})
    assert sentence(policy.statements[0]) == (
        "DENIES every action EXCEPT s3:GetObject on every resource (*) "
        "for the identity this policy is attached to, only when aws:SecureTransport is false.")
