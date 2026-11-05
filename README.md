# ecr-image-scan-gate

[![ci](https://github.com/moveeeax/ecr-image-scan-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/ecr-image-scan-gate/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/moveeeax/ecr-image-scan-gate)](https://goreportcard.com/report/github.com/moveeeax/ecr-image-scan-gate)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![go](https://img.shields.io/badge/go-1.26%2B-00ADD8.svg)](go.mod)

A vulnerable image passes CI silently unless someone opens the scan tab in the
console. `ecr-image-scan-gate` turns Amazon ECR image scan findings into an
**exit code**, so a HIGH/CRITICAL CVE fails the pipeline instead of shipping.

- Reads scan findings live via the AWS SDK, **or** offline from a
  `describe-image-scan-findings` JSON dump.
- Aggregates counts per severity and lists the top findings (CVE + package).
- `--fail-on <severity>` exits non-zero when any finding is at or above the
  threshold. Default gate is `high`.
- `--allow <cve>` allowlists known-accepted CVEs so they never fail the gate.
- Table (default) or `--output json` for machine consumption.

Exit codes: `0` clean, `1` gate tripped, `2` usage/runtime error.

## Install

Requires Go 1.26 or newer.

```sh
go install github.com/moveeeax/ecr-image-scan-gate/cmd/ecr-image-scan-gate@latest
```

Or build from source:

```sh
git clone https://github.com/moveeeax/ecr-image-scan-gate
cd ecr-image-scan-gate
go build -o ecr-image-scan-gate ./cmd/ecr-image-scan-gate
```

## Usage

Gate the tag you just pushed (live, uses the ambient AWS credentials):

```sh
ecr-image-scan-gate scan --repo my-service --tag "$GIT_SHA" --fail-on high
```

By digest:

```sh
ecr-image-scan-gate scan --repo my-service --digest sha256:abc... --fail-on critical
```

Offline against a dump — no AWS calls, fully deterministic:

```sh
aws ecr describe-image-scan-findings \
  --repository-name my-service --image-id imageTag=1.4.2 > findings.json

ecr-image-scan-gate scan --input findings.json --fail-on high
```

```
Image: my-service @ 1.4.2
SEVERITY       COUNT
CRITICAL       1
HIGH           1
MEDIUM         1
LOW            1
INFORMATIONAL  0
UNDEFINED      0
TOTAL          4

Top findings:
  SEVERITY  CVE            PACKAGE
  CRITICAL  CVE-2022-4304  openssl 3.0.7-r0
  HIGH      CVE-2023-0464  openssl 3.0.7-r0
  MEDIUM    CVE-2021-3999  glibc 2.35-r0
  LOW       CVE-2020-1234  zlib

Gate: fail-on=HIGH -> FAILED
```

JSON output (severities are self-describing strings):

```sh
ecr-image-scan-gate scan --input findings.json --output json
```

Allowlist an accepted CVE so it does not fail the build:

```sh
ecr-image-scan-gate scan --input findings.json --fail-on high --allow CVE-2023-0464
```

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--repo` | | ECR repository name (live mode) |
| `--tag` | | Image tag (live mode) |
| `--digest` | | Image digest `sha256:...` (live mode) |
| `--region` | ambient | AWS region |
| `--input` | | Read a `describe-image-scan-findings` JSON dump instead of calling AWS |
| `--fail-on` | `high` | Gate severity: `critical\|high\|medium\|low\|informational\|undefined` |
| `--output`, `-o` | `table` | `table` or `json` |
| `--top` | `10` | Number of top findings to list |
| `--allow` | | CVE ids to allowlist (repeatable or comma-separated) |

## In GitHub Actions

```yaml
- name: Gate on ECR scan findings
  run: |
    go install github.com/moveeeax/ecr-image-scan-gate/cmd/ecr-image-scan-gate@latest
    ecr-image-scan-gate scan --repo my-service --tag "${GITHUB_SHA}" --fail-on high
```

Configure AWS credentials for the step with
[`aws-actions/configure-aws-credentials`](https://github.com/aws-actions/configure-aws-credentials)
(the ECR permission needed is `ecr:DescribeImageScanFindings`).

## How it works

The severity gate is a **pure function** over a slice of findings
([`internal/gate`](internal/gate)): it aggregates counts, applies the CVE
allowlist, sorts the top findings deterministically, and decides whether the
threshold is crossed. It performs no I/O, which is what makes the whole gate
unit-testable offline against JSON fixtures. Live AWS access lives in a thin
[`internal/awsecr`](internal/awsecr) wrapper behind an interface, so tests
inject a fake client and never touch AWS.

## License

MIT — see [LICENSE](LICENSE).
