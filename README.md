# iam-policy-explain

Explain an AWS IAM policy in plain English and flag wildcards, privilege escalation paths and public access.

**Status: working first version (0.1.0).** It reads policy JSON from files or stdin, describes every statement, runs the risk checks listed below, answers "does this policy allow action X on resource Y?" and sets an exit code for CI. It is fully offline: it has no dependencies, never calls AWS and needs no credentials. Reading a policy straight from an ARN is not built yet.

## Install

```bash
pip install git+https://github.com/narayana006/iam-policy-explain
```

Python 3.10 or newer. Standard library only.

## Quick start

The repository ships four sample policies in `examples/`. This is the real output for the S3 bucket policy:

```console
$ iam-policy-explain examples/bucket-policy.json --account 123456789012
examples/bucket-policy.json: 4 statement(s), resource-based policy (has Principal)

[1] ALLOW  PublicReadAssets
    who:   anyone (*)
    what:  s3:GetObject
    where: arn:aws:s3:::example-site-assets/public/*
[2] ALLOW  PartnerUpload
    who:   AWS: arn:aws:iam::210987654321:role/partner-uploader
    what:  s3:PutObject, s3:AbortMultipartUpload
    where: arn:aws:s3:::example-site-assets/incoming/*
[3] ALLOW  OrgWideList
    who:   anyone (*)
    what:  s3:ListBucket
    where: arn:aws:s3:::example-site-assets
    when:  aws:PrincipalOrgID equals o-exampleorgid
[4] DENY  DenyInsecureTransport
    who:   anyone (*)
    what:  s3:*
    where: arn:aws:s3:::example-site-assets, arn:aws:s3:::example-site-assets/*
    when:  aws:SecureTransport is false

Findings (3):
  CRITICAL PUBLIC                 statement 1 (PublicReadAssets) allows anyone ("*"), including anonymous callers and every AWS account: public access.
  MEDIUM   CROSS_ACCOUNT          statement 2 (PartnerUpload) grants access to principals in another account (210987654321).
  MEDIUM   PUBLIC_WITH_CONDITION  statement 3 (OrgWideList) names anyone ("*") as principal, restricted by a condition on aws:PrincipalOrgID. The condition is not evaluated here; confirm it is tight enough.
$ echo $?
1
```

The exit code is 1 because one finding is `high` or worse (the default threshold).

For an identity policy the privilege-escalation checks come into play. The findings section for `examples/developer-policy.json`:

```console
$ iam-policy-explain examples/developer-policy.json
...
Findings (8):
  HIGH     PASSROLE_ANY_ROLE      statement 2 (LaunchInstances) allows iam:PassRole on every role with no iam:PassedToService condition: any role in the account can be handed to a service.
  HIGH     PRIVESC                Privilege escalation via iam:PassRole + ec2:RunInstances (statement 2): can launch an EC2 instance with a more privileged role and use its credentials.
  HIGH     PRIVESC                Privilege escalation via iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction (statements 2, 4): can create and invoke a Lambda function that runs as a more privileged role.
  HIGH     PRIVESC                Privilege escalation via iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping (statements 2, 4): can create a Lambda function with a more privileged role and trigger it from an event source.
  MEDIUM   WILDCARD_RESOURCE      statement 2 (LaunchInstances) applies to every resource ("*") for actions that are not only Describe*/List*.
  MEDIUM   PRIVESC                Privilege escalation via iam:CreateAccessKey (statement 3): can create access keys for another, more privileged user. Every grant involved is limited by resource or Condition; check whether the limit actually prevents this.
  MEDIUM   PRIVESC                Privilege escalation via lambda:UpdateFunctionCode (statement 4): can replace the code of an existing Lambda function and run as its role. Every grant involved is limited by resource or Condition; check whether the limit actually prevents this.
  MEDIUM   WILDCARD_SERVICE       statement 4 (LambdaFromOffice) allows every lambda action ("lambda:*") (has a Condition, which is not evaluated here).
```

## Usage

```
iam-policy-explain [FILE ...] [--json] [--fail-on LEVEL] [--account ID] [--can ACTION [--on RESOURCE]]
```

| Option | Meaning |
| --- | --- |
| `FILE ...` | One or more policy JSON files. `-` or no file reads stdin. |
| `--json` | Machine-readable output (one object, or a list when several files are given). |
| `--fail-on LEVEL` | Exit 1 if any finding is at this severity or higher: `info`, `low`, `medium`, `high` (default), `critical`, or `never`. |
| `--account ID` | Your 12-digit account id. With it, principals from other accounts are reported as `CROSS_ACCOUNT`; without it they are listed as `info`. |
| `--can ACTION` | Also check whether the policy allows this action, e.g. `s3:GetObject`. |
| `--on RESOURCE` | Resource ARN for `--can`. |

Exit codes: `0` no finding at or above the threshold, `1` at least one, `2` the input could not be read or is not an IAM policy.

### Input formats

A bare policy document, or the JSON printed by these AWS CLI commands (the tool finds the document inside):
`aws iam get-policy-version`, `aws iam get-role` (the trust policy), `aws iam get-role-policy` / `get-user-policy` / `get-group-policy`, and `aws s3api get-bucket-policy` (policy as an embedded JSON string).

```bash
aws iam get-policy-version --policy-arn "$ARN" --version-id v1 | iam-policy-explain
```

You run the `aws` command yourself; this tool only reads what you pipe in.

### Checking one action

`--can` applies the rules that can be decided from a single document: an explicit Deny that matches always wins; with no matching Allow the answer is an implicit deny; anything that depends on a Condition, a policy variable or a named principal is reported as `CONDITIONAL` rather than guessed.

```console
$ iam-policy-explain examples/developer-policy.json --fail-on never \
    --can s3:DeleteObject --on arn:aws:s3:::example-audit-logs/2026/01.gz
...
Check: EXPLICIT_DENY  s3:DeleteObject on arn:aws:s3:::example-audit-logs/2026/01.gz is explicitly denied by statement 5 (NeverTouchAuditLogs); an explicit deny overrides every allow.
    DENY  statement 5 (NeverTouchAuditLogs): matches

$ iam-policy-explain examples/bucket-policy.json --fail-on never \
    --can s3:GetObject --on arn:aws:s3:::example-site-assets/public/logo.png
...
Check: CONDITIONAL  s3:GetObject on arn:aws:s3:::example-site-assets/public/logo.png matches an Allow, but statement 4 (DenyInsecureTransport) may deny it depending on things this tool does not evaluate.
    ALLOW statement 1 (PublicReadAssets): matches
    DENY  statement 4 (DenyInsecureTransport): may match: it has a Condition block, which is not evaluated
```

The four results are `ALLOWED`, `EXPLICIT_DENY`, `IMPLICIT_DENY` and `CONDITIONAL`. If `--on` is omitted, only statements with `"Resource": "*"` count as certain matches.

## What it checks

Only `Allow` statements produce findings; `Deny` statements are explained but never flagged.

| Code | Severity | Triggered by |
| --- | --- | --- |
| `ADMIN` | critical | `Action: *` on `Resource: *` with no Condition |
| `ADMIN_CONDITIONAL` | high | the same, but with a Condition |
| `WILDCARD_ACTION` | high | `Action: *` on specific resources |
| `WILDCARD_SERVICE` | medium (high for iam, sts, organizations, kms) | `service:*` |
| `WILDCARD_RESOURCE` | medium | `Resource: *` for actions other than `Describe*` / `List*` |
| `ALLOW_NOT_ACTION` | high | `Allow` with `NotAction` (allows everything not listed) |
| `ALLOW_NOT_RESOURCE` | medium | `Allow` with `NotResource` |
| `PASSROLE_ANY_ROLE` | high | `iam:PassRole` on `*` without an `iam:PassedToService` condition |
| `PRIVESC` | high (medium if every grant involved is resource-scoped or conditional) | one of 24 known escalation paths, e.g. `iam:CreatePolicyVersion`, or `iam:PassRole` + `ec2:RunInstances`; combinations may be spread over several statements |
| `PUBLIC` | critical | `Principal: *` or `{"AWS": "*"}` with no condition that restricts the caller |
| `PUBLIC_WITH_CONDITION` | medium | the same, with a positive condition on a key such as `aws:PrincipalOrgID`, `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceVpce` or `aws:SourceIp` |
| `CROSS_ACCOUNT` | medium | a principal from an account other than `--account` |
| `ACCOUNT_PRINCIPAL` | info | an account principal when `--account` was not given |
| `ALLOW_NOT_PRINCIPAL` | high | `Allow` with `NotPrincipal` |
| `FEDERATED_NO_CONDITION` | high | a `Federated` principal trusted with no Condition |
| `OLD_VERSION` | low | `Version` missing or not `2012-10-17` |

How matching works:

- Action names are compared case-insensitively; `*` and `?` are wildcards. Resource ARNs are compared case-sensitively.
- `NotAction` and `NotResource` match everything except what they list. In an `Allow` that is a grant of everything else; it does not deny the listed items.
- A privilege-escalation path is dropped only when an unconditional `Deny` on `Resource: *` covers one of its actions. A Deny that is scoped or conditional does not suppress the finding.
- `${*}`, `${?}` and `${$}` are treated as literal characters; any other `${...}` is an unresolved policy variable.

## Features

- [x] Plain-English summary of who can do what on which resources
- [x] Flags `*` actions and resources
- [x] Flags known privilege-escalation combinations
- [x] Flags public or cross-account access
- [x] Works on files and stdin
- [x] Exit code for use in CI
- [x] Single-policy check for one action and resource (`--can` / `--on`)
- [ ] Read a policy directly from a policy ARN
- [ ] Expand wildcards into the full list of matching AWS actions

## What it does not do

Be clear about these before relying on the output:

- **It looks at one policy document at a time.** Real access is decided by all identity policies, resource policies, permissions boundaries, service control policies, resource control policies and session policies together. `ALLOWED` here means "this document allows it", not "the request will succeed".
- **Conditions are described, not evaluated.** The tool cannot know the request context (source IP, MFA, tags, time), so a statement with a Condition is always reported as conditional. The `PUBLIC_WITH_CONDITION` downgrade only checks that a caller-restricting key is present with a positive operator, not that its value is safe.
- **Policy variables are not resolved.** A resource containing `${aws:username}` is matched as if the variable were a wildcard, and the result is marked conditional.
- **Principals are not evaluated in `--can`.** A resource-policy statement for a named principal is reported as conditional because the tool does not know who is asking.
- **No AWS action catalog is bundled.** Wildcards are matched against the built-in list of escalation actions and against the action you pass to `--can`; the tool does not list every action that `s3:Get*` expands to, does not know which actions support resource-level permissions, and does not catch misspelled action names.
- **The escalation list is a fixed set of 24 well-known paths**, not a complete analysis. A policy with no `PRIVESC` finding can still allow escalation by another route.
- **Resource matching is a plain wildcard match over the whole ARN.** Service-specific rules are not modelled.
- It does not validate policy grammar beyond what it needs to parse (Effect, Action/NotAction, Resource/NotResource, Principal/NotPrincipal, Condition).

For authoritative answers use the IAM policy simulator and IAM Access Analyzer; this tool is for reading and reviewing policies quickly, for example in a pull request.

## Use in CI

```yaml
- run: pip install git+https://github.com/narayana006/iam-policy-explain
- run: iam-policy-explain policies/*.json --account 123456789012 --fail-on high
```

## Development

```bash
git clone https://github.com/narayana006/iam-policy-explain
cd iam-policy-explain
pip install -e ".[dev]"
pytest
```

## Contributing

Issues and pull requests are welcome, especially false positives or false negatives with a minimal policy that reproduces them, and additional escalation paths with a public reference.

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
