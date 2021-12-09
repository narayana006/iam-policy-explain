# iam-policy-explain

Explain an AWS IAM policy in plain English and flag wildcards, privilege escalation paths and public access.

> **Project status: planning. There is no working code in this repository yet.**
> This README describes what the project will do. Nothing below can be installed or run today.
> Features are ticked off in the checklist as they are built.

## What it is

A command-line tool.

**The problem it solves:** IAM policy JSON is hard to read, and risky statements hide behind wildcards and conditions.

## Who it is for

Engineers and reviewers who need to understand an IAM policy before approving it.

## How it will work

1. You give the tool a policy file or ARN.
2. It parses every statement and expands the action wildcards.
3. It prints what the policy allows and lists anything risky.

## Planned features

Unticked items are not built yet.

- [ ] Plain-English summary of who can do what on which resources
- [ ] Flags `*` actions and resources
- [ ] Flags known privilege-escalation combinations
- [ ] Flags public or cross-account access
- [ ] Works on files, stdin or a policy ARN
- [ ] Exit code for use in CI

## Planned usage

This is the intended interface, shown so you can judge the design. **It does not work yet**, and names may change before the first release.

```bash
iam-policy-explain policy.json
```

## Contributing

Feedback on the design is the most useful contribution right now. Open an issue to suggest a feature, question an approach or describe your use case. Code contributions are welcome once the first version lands.

## Author

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
