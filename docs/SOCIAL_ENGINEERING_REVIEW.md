# HunterQA — Social Engineering review

Two offline assurance contracts and selected saved evidence checks support approved
simulation and participant-protection review. This is partial coverage, not a
campaign sender, targeting tool, credential collector or social-engineering attack engine.

| Upstream skill ID | Implemented review coverage | Independent evidence still needed |
| --- | --- | --- |
| `offensive-phishing` | Authorization/scope/mail/content/privacy observations; selected DMARC declarations and simulation config flags | Actual owner approval, DNS/mail authentication, receiver behavior, consent/scope and transport/privacy enforcement |
| `offensive-social-engineering` | Channel/identity/physical/media/stop/follow-up observations; aggregate saved GoPhish latest-result metadata | Actual participant behavior, exercise provenance and training effectiveness; non-email channels use owner observations only |

## Start privately

1. Record owner authorization, local evidence scope, approved exercise design,
   reviewer and provenance. A local acknowledgment is not independently verified consent.
2. Copy [the JSON template](../templates/HunterQA-social-review-template.json) and
   [worksheet](../templates/24-social-engineering-review.md) outside this repository.
   Prefer minimized result exports. Do not supply real credentials or submitted
   values; campaign exports can contain recipient and SMTP/profile secrets.
3. Set `HUNTERQA_APPROVED_ROOTS` to the narrow absolute private directory covering
   inputs and output parent. Keep even aggregate reports private, especially for
   small cohorts; never commit recipient exports, agreements or completed worksheets.
4. Set observations to `true` for supported assurance review, `false` for an
   assurance gap, or `null` for unassessed. Keep private supporting references in
   the worksheet, not extra JSON fields. Choose a fresh report filename; no overwrite.
5. Select the saved-evidence mode; HunterQA does not connect to DNS, SMTP, GoPhish
   APIs, participants or referenced URLs, and never creates or launches a campaign.

```text
hunterqa social-review-catalog
hunterqa social-review --input /absolute/private/observations.json --out /absolute/private/review.json --authorized
hunterqa social-evidence-review --mode dmarc-text --input /absolute/private/dmarc.txt --out /absolute/private/dmarc-report.json --authorized
hunterqa social-evidence-review --mode gophish-results-json --input /absolute/private/results.json --out /absolute/private/results-report.json --authorized
```

PowerShell: `$env:HUNTERQA_APPROVED_ROOTS = 'C:\Private\HunterQA'`, with Windows
absolute paths. Linux: `export HUNTERQA_APPROVED_ROOTS=/absolute/private`.

## Saved DMARC TXT declaration

Input is one concatenated UTF-8/BOM TXT value, not a DNS zone file, quoted DNS
chunk output or a collection of records. Selected tags: `v`, `p`, `sp`, `np`, `t`,
legacy `pct`, `adkim`, `aspf` and reporting-URI presence. `v=DMARC1` must be first;
duplicate/malformed tags and malformed selected enum/numeric values fail. Unknown
tag values are not evaluated. Reporting URIs are neither exported nor followed.

The reader references RFC 9989: `p` is recommended rather than mandatory, testing
uses `t`, and `pct` is legacy/removed. Explicit `none` preferences, `t=y` and
legacy `pct` presence yield review cues. Percentage-based policy is not computed.
Missing declarations remain unknown; this reader does not apply defaults, domain
policy discovery, inheritance or testing-mode transformations. Review migration
and actual receiver compatibility before changing a production policy.

No SPF/DKIM signature/alignment verification, DNS lookup, organizational-domain
selection, reporting authorization, full DMARC grammar/URI validation or message
disposition evaluation is performed. A `reject` declaration or no findings does
not prove protection against phishing, account compromise or impersonation.

## Saved GoPhish result/config metadata

Input is one saved campaign/results JSON object with a `results` array, not a list
of campaigns, timeline export or direct API connection. Only each row's `status`
and optional boolean/null `reported` are examined. Recognized latest-state labels
are `Email Sent`, `Email Opened`, `Clicked Link`, `Submitted Data`; all other/missing
labels go to `other_or_unknown`. Reported true/false/unknown counts are independent
of status counts and must not be added to them as a recipient total.

Optional saved full-campaign metadata can include boolean/null
`page.capture_credentials`, `page.capture_passwords`, `smtp.ignore_cert_errors`.
Explicit true flags and declared submitted-data outcomes yield privacy/transport
review cues; this does not establish actual collection or delivery. Submitted
values, timeline, names, email/IP addresses, IDs, dates, message/page content and
SMTP credentials are not analyzed or exported. Unknown fields are ignored.

Output is aggregate counts and selected flags only. Counts represent source rows,
not unique people, deduplicated recipients, cumulative event funnels, rates or
training effectiveness. Opens/clicks/submissions can result from automated
scanners, proxies, source errors or other non-human activity. No participant
identity or behavior is verified; provenance and actual approval remain unverified.

No mail/SMS/voice delivery, pretext generation, identity targeting, impersonation,
MFA proxying, credential harvesting, page cloning, payloads, physical entry, media
injection or contact-list harvesting is implemented. The upstream skill IDs are
review-topic references, not availability of those operations.

## Reports, bounds and verification

Reports retain SHA-256 input receipts, generic case numbers, selected policy enums,
booleans and aggregate counts. Names, addresses, domains, identifiers, URLs,
credentials, content and timestamps are withheld. Findings are `INFO`, unverified
review candidates with generic remediation guidance; conservative SARIF export
omits source locations. Input hashes do not prove collection integrity or consent.

Inputs require explicit authorization and approved-root regular non-symlink files
of at most 1 MiB. Strict JSON rejects duplicate keys, nonfinite numbers, excessive
depth/nodes and malformed selected fields. Bounds: 10 observations per skill/20
total; DMARC 16,384 characters/100 tags/4,096 characters per value; 1,000 saved
result rows and status strings at most 64 characters; 500 retained findings with
explicit truncation counts. Invalid-input errors withhold contents. Approved roots
reduce accidental access, not hostile concurrent filesystem mutation.

Owned synthetic tests cover policy updates/default limits, result aggregation,
unknown states, redaction, parser/file bounds, authorization, no-overwrite, SARIF
and absence of process/network execution. All seven broad readiness areas remain
partial, and real-world effectiveness remains unverified.

## References and next category

- [Upstream category](https://github.com/SnailSploit/Claude-Red/tree/main/Skills/social-engineering)
- [RFC 9989: DMARC](https://www.rfc-editor.org/rfc/rfc9989.html)
- [GoPhish campaign/results format](https://docs.getgophish.com/api-documentation/campaigns)

**Next requested category: Network.** It is not delivered by this pack.
