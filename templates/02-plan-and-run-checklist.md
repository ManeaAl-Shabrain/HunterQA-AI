# 02 · Plan and Run Checklist

Fill this private worksheet alongside the commands in the folder README and
original instructions. This checklist does not run or authorize a request.

## Configuration

- [ ] HunterQA version recorded: [Fill]
- [ ] Virtual environment active.
- [ ] Canonical absolute case directory: [Fill]
- [ ] `HUNTERQA_APPROVED_ROOTS` points to that private directory.
- [ ] `profile.json` contains the real approval reference and exact allowed scope.
- [ ] `targets.txt` contains one exact approved endpoint for the first run.
- [ ] The profile and command use the same approved GET or HEAD method.
- [ ] Initial per-invocation request budget is one.
- [ ] Owner exclusions, testing window and total remaining allowance checked.

## Offline preflight

| Item | Record actual result |
| --- | --- |
| Planned endpoint | [Full approved URL; no credentials] |
| Planned method | [GET / HEAD] |
| Planned output | [Fresh filename, e.g. header-review-001.json] |
| Preflight time and timezone | [Fill] |
| Preflight result | [Fill only after running bounty-preflight] |
| Reviewer/operator reference | [Fill] |

- [ ] All scope/configuration failures resolved against the actual permission.
- [ ] The planned output file does not already exist.
- [ ] I understand the next bounty-assess command sends traffic.

## Execution

| Item | Fill after the actual run |
| --- | --- |
| Start/end and timezone | [Fill] |
| Exact command/method | [Record without secrets] |
| Output file | [Private path] |
| Observed result/error | [Observed, failed or inconclusive] |
| Total allowance remaining | [Update using actual/possible attempts] |
| Owner contact/stop action, if needed | [Fill] |

`bounty-assess` does not use another command's STOP file. Ctrl+C requests
interruption, but a sent/in-flight operation cannot necessarily be recalled.
Record uncertain attempts conservatively and do not retry automatically.

Continue with `03-findings-and-report.md`; do not equate execution success with
a confirmed vulnerability or an empty result with complete security coverage.
