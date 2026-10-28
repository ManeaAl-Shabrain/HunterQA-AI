# 04 · Retest Record

A retest is another assessment invocation. Confirm that permission, scope,
window and the owner's remaining total request allowance still cover it.

## Before retesting

- [ ] Owner permission remains current and covers the retest action.
- [ ] The endpoint, method and relevant context match the intended comparison.
- [ ] Any scope changes are reflected in a reviewed private profile.
- [ ] Testing window and remaining total allowance checked.
- [ ] A fresh output filename is selected, e.g. `header-review-002.json`.
- [ ] Original evidence is preserved; no prior report will be overwritten.

| Item | Actual record |
| --- | --- |
| Original candidate/report | [Private reference] |
| Owner's reported change | [Record as an owner assertion until assessed] |
| Retest approval reference | [Fill] |
| Retested endpoint and method | [Fill] |
| Start/end and timezone | [Fill] |
| New evidence file | [Fill] |
| Relevant original observation | [Fill] |
| Relevant retest observation | [Fill] |
| Outcome | [Still observed / not observed / inconclusive / not assessed] |
| Independent impact validation | [Fill or not performed] |
| Reviewer and next action | [Fill] |

Compare these basic `bounty-assess` outputs manually. `workflow-compare` applies
to supervised workflow run directories, not these standalone JSON files.

A candidate that is not observed is not automatically a verified repair. A
different status, redirect, content type, missing cookie, failed request or
changed test context can make comparison inconclusive. Record uncertainty and
coordinate any further testing rather than repeatedly sending requests.
