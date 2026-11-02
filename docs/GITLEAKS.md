# Gitleaks rule integration

The replacement detector enables **217 of 222 default rules**, pinned to
[Gitleaks commit `5f6ec56`](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml).
The upstream MIT license is included in `extension/licenses/GITLEAKS.txt` and
copied into the unpacked build and packages.

Keep the Gitleaks source header, pinned upstream URL and MIT copyright/license
notice when editing or repackaging the detector. These preserve the rules'
provenance and required attribution.

All rules that work without a filename are enabled. This includes the initial
families below plus Slack, Stripe, npm, Azure, GitLab, Databricks, DigitalOcean,
SendGrid, Twilio, Postman, Shopify and the remaining provider formats. The full
rule IDs and original expressions are in `src/gitleaks-rules.js`; the feature
tracker lists all 222 upstream rules individually. No rules or code are fetched
from the network at runtime.

| Rule ID | Detection scope |
| --- | --- |
| `generic-api-key` | Assignment patterns with entropy greater than 3.5, stopwords and exclusions |
| `openai-api-key` | Legacy, project, service-account and admin patterns containing the upstream `T3BlbkFJ` marker |
| `anthropic-api-key` | `sk-ant-api03-` pattern |
| `anthropic-admin-api-key` | `sk-ant-admin01-` pattern |
| `gcp-api-key` | `AIza` pattern, entropy greater than 4 and upstream public-key exclusions |
| `github-pat` | `ghp_` personal access tokens |
| `github-fine-grained-pat` | `github_pat_` fine-grained tokens |
| `github-oauth` | `gho_` OAuth tokens |
| `github-app-token` | `ghu_` and `ghs_` app tokens |
| `github-refresh-token` | `ghr_` refresh tokens |
| `aws-access-token` | AWS access-key IDs with the upstream prefix/alphabet, entropy and example exclusion |
| `private-key` | Multiline private-key blocks matching the upstream marker and minimum-length expression |
| `jwt` | Signed or unsigned JWT-shaped values meeting upstream segment, boundary and entropy requirements |
| `curl-auth-header` | Matching authorization and API-key/token headers in cURL commands, entropy greater than 2.75 |
| `curl-auth-user` | Matching cURL `-u`/`--user` credentials, entropy greater than 2 and upstream placeholder exclusions |

Many provider formats work without a nearby field name. All upstream keyword
prefilters still apply: for example, the Airtable personal-token rule requires
the word `airtable` somewhere in the prompt. A keyword alone does not identify a
secret, and no unrestricted whole-prompt guessing is restored.
Their format-specific lengths, boundaries, character sets, entropy thresholds
(where present), prefilter keywords and applicable allowlists remain intact.
These rules identify patterns, not whether credentials are active or valid.
The AWS rule does not detect arbitrary standalone secret access keys or session
tokens. The OpenAI rule does not match every string starting with `sk-`.
Private-key and JWT rules also work without field names. The private-key rule
matches RSA, EC, OpenSSH, encrypted and other recognized private-key block shapes.
It is not a PEM parser: it can accept mismatched marker types or non-key body text
when they satisfy the upstream expression. Short or unfinished blocks may not
match. The JWT rule does not decode claims, check a signature or prove that the
token grants access. The separate `jwt-base64` pattern remains enabled alongside
the bounded decoding passes described below.

## Rule selection by ID

All **217 rules stay enabled by default**. A caller can restrict one scan to
exact, case-sensitive bundled IDs using the fourth `scan`/`redact` argument:

```js
redact(prompt, policy, undefined, { ruleIds: ['github-pat', 'generic-api-key'] });
```

The asynchronous browser API accepts this in its third argument:

```js
SecretShieldScanner.redact(prompt, policy, { ruleIds: ['github-pat'], signal });
```

Omitted/undefined `ruleIds` and `[]` use the full catalog, following the pinned
[Gitleaks `--enable-rule` behavior](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/cmd/root.go#L308).
A nonempty array runs only those rules on plaintext and every decoded pass.
Duplicates are removed and catalog order determines overlap precedence. IDs are
copied for each call. Unknown IDs, the five excluded filename rules, malformed
values, sparse arrays and selections longer than 1,000 entries fail the entire
scan, even for empty input. Comma-separated strings, wildcards and case folding
are not accepted. The complete catalog still undergoes initialization validation.

Composite primaries need every required supporting ID included in the selection;
an unselected support cannot satisfy them. Selected `skipReport` rules still
provide support without public findings. The pinned production catalog has no
composites. Global, local and targeted shared allowlists keep their existing
scope, and selected findings retain metadata, decoding tags and original locations.
Custom-field detection and the Protect client IDs preference operate independently
of Gitleaks rule selection. They are not selectable catalog IDs.

This is a per-call scanner option. It does not save preferences or change the
automatic chat guard, which continues using every default rule. The private
worker transports and revalidates selection, and its caller rejects returned
unselected rule IDs. Cancellation, deadlines, cleanup and retry remain active.
No UI, History, storage, permission or dependency change is needed.

## Engine behavior

`src/gitleaks-rules.js` contains the pinned expressions, the generic rule's full
1,446-entry stopword list, provider allowlists and global content exclusions.
Original Go expressions are retained for comparison. `src/core.js` compiles and
validates the data, prefilters keywords, extracts the selected capture group
(or the entire match for rules without captures), applies entropy and evaluates
secret/match/line exclusions. Findings contain original offsets and line/column
locations, a rule ID, its pinned description, and any configured rule tags followed
by optional encoding/decode-depth tags described below.
When `secretGroup` is zero, extraction uses the first populated capture, falling
back to the whole match if none is populated, as in Gitleaks. Explicit groups
continue to use their configured capture.
Whole-match extraction trims leading and trailing LF delimiters, preserving
surrounding text and the upstream entropy input.

Shared allowlists in the bundled `SecretShieldRules.globalAllowlists` data may
include `targetRules`, an array of exact enabled Gitleaks rule IDs. A nonempty
array attaches that exclusion only to those rules; it is not evaluated globally.
An omitted or empty array retains global behavior. Duplicate IDs are collapsed.
Malformed targets, unknown or excluded IDs, and nonempty `targetRules` on a
per-rule allowlist fail initialization and block the scan. Source catalog data
is not mutated, and a failed initialization does not cache a partial detector.
This follows upstream [shared allowlist assignment](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/config.go).

Scoped lists reuse the existing secret/match/line targets, stopwords, AND/OR
conditions and prompt-only path semantics. Global, per-rule and shared exclusions
combine through the same rule checks, including after decoding. An exception for
`generic-api-key` does not suppress another rule matching the same value, or
explicit custom-field and supplemental client-ID findings. For example:

```js
// Bundled catalog data, not a dashboard preference or runtime import API.
{
  targetRules: ['generic-api-key', 'curl-auth-user'],
  condition: 'OR',
  regexTarget: 'secret',
  regexes: ['^synthetic-approved-fixture$'],
  stopwords: [],
  paths: []
}
```

The pinned production catalog is unchanged and contains no targeted shared
lists. This adds configuration compatibility without introducing new default
exceptions. It does not add an allowlist editor, custom-regex/TOML import,
managed/local preference fields, Chrome permissions or network requests.

### Rule descriptions and configured tags

Every enabled Gitleaks rule includes its exact description from the pinned
catalog. Findings retain the existing `type` rule ID and add `description` when
configured. Optional rule-defined `tags` are returned in source order, including
duplicates, followed by the canonical encoding/decode-depth suffix when present.
The pinned catalog defines no rule tags; none are invented. Empty or omitted tag
arrays produce no `tags` field unless decoding contributes one. An explicitly
empty description is preserved; an omitted description stays absent.

Metadata is attached after overlap selection. The retained type's description
and rule tags describe that review item, while encoding tags still combine
provenance across its merged span. Tags from discarded overlapping rules or
hidden supporting rules are not attributed to the retained rule. This follows
upstream [finding metadata assignment](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/detect.go),
with the existing browser adaptation of merging overlapping findings.
Standalone custom-field and client-ID findings do not receive invented Gitleaks
metadata; their existing optional encoding tags continue to work.

Descriptions are bounded at 2,048 UTF-16 characters, with at most 64 nonempty
rule tags of up to 256 characters each. Malformed metadata fails initialization
without caching partial state. Compiled tag arrays are copied, and returned tags
are independent between occurrences and scans. Reserved-looking configured tags
remain literal prefix values, separate from the generated decoding suffix.
The private worker validates the exact configured description and tag prefix,
then the existing canonical decoding suffix and exact masked text. Missing or
altered metadata blocks sending and permits a fresh scan. No descriptions, tags,
raw matches, or decoded values are added to popup markup, counters or History.
No detection expressions, exclusions, settings or permissions change.

### Original-prompt locations

Every returned finding includes `startLine`, `startColumn`, `endLine` and
`endColumn`, computed from its final original `start`/`end` masking span after
decoding and overlap merging. This applies to provider rules, generic rules,
custom fields, supplemental client IDs and retained composite primaries.
Hidden supporting matches do not gain public location fields.

Lines and UTF-8 byte columns start at one. The end location includes the last
byte in the span, while existing editor offsets remain UTF-16 with an exclusive
end. LF advances the line and resets the next column to one. CR and tabs each
count as a byte, so CRLF advances the line once and bare CR does not. An included
LF belongs to the preceding line at its next byte column. Unicode characters
occupy their UTF-8 byte lengths, and lone surrogates count as the three-byte
replacement character used by UTF-8 encoding. A span cannot split a surrogate
pair. Locations always refer to the original draft, including coarse encoded
blobs and merged spans, rather than temporary decoded text or the masked output.

The [upstream location fields](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/report/finding.go)
also use byte columns, but describe the full regex match before capture extraction.
The browser reports the final masking span instead. It also normalizes LF column
origins and correctly closes multiline spans on an unterminated final line,
rather than reproducing the pinned upstream location routine's edge cases.
Existing composite proximity checks retain their own upstream full-match-start
coordinates and are unchanged by these public location fields.

The mapper advances once through the original text across sorted disjoint
findings. Its work is linear in the examined text and finding count, without
per-finding prefix rescans or persistent caches. The private worker recomputes
all four coordinates from the original spans and rejects missing or altered
values before a result can enter review. Cleanup and retry use the existing
failure flow. These are response fields only; popup content, counters, History,
preferences, permissions, detection expressions and exclusion rules do not change.

### Composite rules

Bundled rules may declare `required: [{ id, withinLines?, withinColumns? }]`.
A primary finding is retained only when every named rule ID has an accepted
supporting match in the same scan pass. Without distance limits, any match in
that prompt fragment qualifies. Bounds are inclusive absolute distances between
the starts of the **full regex matches**, before secret-group extraction.
`withinLines: 0` requires the same LF line. `withinColumns` alone does not require
nearby lines. When both are present, the same supporting match must satisfy both.
Repeated required IDs provide alternative bounds for that ID, following the
upstream collect-by-ID behavior.

Columns count UTF-8 bytes, including upstream's preceding-LF origin: the first
character of the first line is column 1; immediately after LF it is column 2.
A match beginning on LF belongs to the following line at column 1. CR alone is
not a line break. These internal coordinates follow the pinned
[Gitleaks detector](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/detect.go)
and [location calculation](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/location.go).
Public editor offsets remain UTF-16.

Supporting candidates pass the usual capture, entropy and global/per-rule/shared
allowlist checks. Their own keyword prefilters and dependencies are bypassed,
as in upstream auxiliary detection; references do not recursively evaluate a
dependency graph. Self and mutual references therefore remain bounded. Primary
keyword prefilters still apply. Boolean `skipReport: true` suppresses a rule's
standalone findings while allowing it to support another rule. Hidden support
does not independently enter review, masking, counters or History. Other rules
matching that text, explicit custom fields and supplemental client IDs keep
their normal behavior.

After decoding, full-match starts map back to the original input before distance
checks. Matches within one encoded segment can share its coarse original start.
The browser engine retains its complete-pass scanning: decoded supporting context
can enable an unchanged plaintext primary on a later pass. Upstream can skip
unchanged primary matches on decoded passes, so this is a deliberate browser
adaptation. Returned findings contain primary original spans, types, configured
rule metadata and applicable encoding tags, with no auxiliary values or location
fields.

Unknown/excluded IDs, malformed `required` entries, nonboolean `skipReport`, or
negative, fractional or unsafe distance integers fail initialization and block
the complete scan without caching partial state. Nonnegative safe integers are
a browser validation constraint; upstream accepts signed distance fields.
Proximity indexes use binary searches, with a shared budget of 1,000,000
dependency checks and examined candidates across original and decoded passes.
Exhaustion fails the complete scan closed; the browser worker deadline also
remains in force.

None of the 222 pinned default rules uses composite dependencies or `skipReport`.
The 217 enabled rules and their default findings are unchanged. This is bundled
engine compatibility, with no new configuration editor, imports, preferences,
permissions, dependencies or network requests.

The regex port expands Go case-folding into explicit character classes, converts
Go's ASCII whitespace and strict end-of-input anchors, including Unicode folds
of word classes under case-insensitive scopes, and avoids modifier-group
syntax so the existing Chrome 120 minimum remains supported. Offsets use UTF-16
indices as required by the existing JavaScript editor and masking APIs. Unicode
regex mode preserves Go's code-point quantifiers, including the private-key
minimum length when the body contains characters outside the BMP. The private
rule's whitespace/complement union still accepts every code point. The catalog
port also translates POSIX ASCII alphanumeric classes, Go named captures and
escaped punctuation into equivalent JavaScript Unicode-regex syntax.

Overlapping provider and generic findings become one review item covering the
union of their spans, with the provider rule ID preferred. Distinct repeated
occurrences remain separate. This is a masking adaptation: upstream's reporting
filter removes some contained generic findings but can retain overlapping
reports. Returning overlapping editor spans would duplicate text during masking.
The Azure client-secret rule reuses its consumed trailing delimiter when looking
for the next credential. Otherwise two values separated by a single newline,
space or comma can leave the second value unmasked. The corpus retains upstream
reports separately from this independently checked browser enumeration.

The cURL rules retain their pinned header/option syntax, case sensitivity,
quotation, line-distance limits, entropy thresholds and exclusions. Basic header
values are matched as encoded text; they are not decoded. User/password matches
include the complete credential pair, including outer quotes when the upstream
capture includes them. No credential or command is sent to a validation service.

For browser masking, cURL authentication options are enumerated individually and
each is checked with the pinned option expression and equivalent command-prefix
constraints, with an anchored end. Counting LF groups separately avoids the
ambiguous CR/dot backtracking of a direct JavaScript port.
This avoids repeatedly searching long command prefixes and includes credentials
skipped by upstream's greedy or non-overlapping command reporting. The reference
corpus preserves both the exact upstream reports and the three intentional
per-option enumeration differences. Other rule matching is unchanged. This is a
prompt-scanning adaptation, not a general shell parser or exact report parity.

The wrapped-JWT rule preserves upstream extraction for entropy and exclusions,
but review and masking cover the complete matched encoded value. Upstream's
first populated named capture contains only an encoded header-field fragment;
masking just that fragment can leave another token in a greedy multiline match.
This deliberate span adaptation is tested against the upstream match text.

```text
api_key = N7q2V9m4R8s6T3x5K1p0L2z7H4c9D6b8
```

This generic example opens the existing review and masks to `api_key = xxxxxxxxxx`.
`key={event.id}` and ordinary API-key discussion do not match. The generic rule's
label, separator, character, length, entropy and exclusion requirements must all
pass. Some alphanumeric/base64 values can exceed 150 characters; that limit
applies to the other candidate branch, not every value.

## Custom-field detection

Saved `sensitiveNames` supplement the pinned rules without changing the upstream
catalog. Both local and managed names match literally, ignoring case, at field
boundaries. For example, saving `dataset_key` protects `dataset_key = 12`,
`dataset_key: demo-value` and `{"dataset_key":"some readable words"}`.
No minimum length or entropy requirement applies to an explicitly configured
field. Its name is an instruction to protect the assigned literal value.

Assignments require `=` or `:`. Values can follow the separator on the same line
or immediately next line. Straight single/double quotes and backticks preserve
spaces, escapes and multiline values; masking changes only the content between
the quotes. Bare values end at whitespace, commas, semicolons, closing brackets,
quotes or a closing angle bracket. Names are not expanded into spelling aliases,
and bare mentions, natural-language `is` phrases and distant values are ignored.
Empty values, recognized placeholders, already masked values, unquoted
`null`/`undefined`/booleans, variable placeholders, object/JSX expressions and
interpolated backtick strings are skipped. An unfinished quoted custom value
fails the scan and keeps the draft local until corrected.

Custom findings contain UTF-16 offsets and `custom-field` as their type, with
encoding tags when their value intersects decoded text.
Overlaps with upstream findings merge into one complete masking span, preferring
the provider type. Equal unbound values are not masked by association. Removing
a field stops its custom matching on the next scan; existing policy-change
handling cancels a pending review. No value is retained by the custom matcher.

## Client-ID setting

**Protect client IDs** is enabled by default. When enabled, the same assignment
parser protects literal values assigned to `client_id`, `clientId`, `client-id`
or `client id`, ignoring case. This includes JSON properties, short/numeric
values, quoted multiline values and values on the immediately next line after
`=`/`:`. The same field boundaries, placeholder/expression exclusions and
incomplete-quote failure behavior apply. Findings use UTF-16 offsets with type
`client-id`; overlaps merge into one complete masking span.

The checkbox applies immediately, persists across reloads and follows managed
policy precedence. Turning it off removes this supplemental matching only.
Explicit custom fields and all 217 pinned Gitleaks rules remain active,
including upstream provider-specific client-ID rules. These SecretGuard additions
do not change the upstream catalog, allowlists or entropy thresholds.

## Encoded text and original spans

The scanner checks the original text, then performs up to three decoding
passes. Each pass replaces valid candidates in a temporary copy and runs the
same 217 rules, custom fields and client-ID preference with their surrounding
label/keyword context intact. Base64 accepts standard and URL-safe alphabets,
with or without valid padding. A candidate requires at least 16 alphabet
characters and must decode entirely to bytes from `0x09` through `0x7e`, matching
the upstream ASCII scope. Binary and non-ASCII UTF-8 payloads, mixed alphabets,
invalid padding and nonzero unused bits are rejected. Candidates split by
whitespace are not joined.

Percent candidates run from the first valid `%HH` escape through the last valid
escape on the same LF-delimited source line, matching Gitleaks' boundaries.
Hexadecimal digits are case-insensitive. Valid escapes decode only to bytes
`0x09` through `0x7e`; any out-of-range escaped byte rejects that entire candidate.
Unescaped text, including Unicode and malformed percent sequences, stays literal.
`+` stays a plus sign; this is not HTML form parsing or URL normalization.
Existing rule syntax still applies: the generic rule can miss a credential
followed by an unsupported delimiter such as `&` in a query string. Decoding does
not add a general query-parameter detector.

Hex candidates contain at least 32 consecutive hexadecimal characters, ignoring
case, with two characters per decoded byte. Odd lengths and candidates containing
decoded bytes outside `0x09` through `0x7e` are rejected completely; invalid
candidates are not retried as Base64. Whitespace-separated chunks are not joined.
Hex decoding does not by itself make a value a secret: the existing rules,
context, entropy and exclusions must still match the resulting text.

Candidate precedence is percent, then hex, then Base64, following the enabled
upstream codecs. A contained encoding can be decoded on the next pass. Mixed
Base64/percent/hex nesting uses the same shared three-pass limit and byte budget.
Unicode-escape decoding remains unimplemented.

Findings are mapped through every decoding pass back to UTF-16 positions in the
original prompt. If a finding intersects decoded text, its span covers that
complete encoded segment; a finding crossing multiple segments also covers the
intervening text. Plain and decoded overlaps merge through the existing masking
path. Partly encoded percent candidates can span ordinary text between their
first and last escapes, so masking can remove intervening non-secret text too.
The review shows the original encoded span, and Mask replaces that whole
span with `xxxxxxxxxx`. It does not re-encode a partial replacement or expose
decoded values as new finding fields. Existing wrapped-JWT span adaptations
remain unchanged. All decoding and rule matching stay local; temporary decoded
text is not saved by the decoder.

Decoded findings also include an optional `tags` array. Encoding tags appear in
the stable order `decoded:percent`, `decoded:hex`, `decoded:base64`, with each
contributing codec included once, followed by one `decode-depth:1` through
`decode-depth:3` tag. Depth is the latest contributing decoding pass, not the
number of different codecs. A twice-hex-encoded token has
`['decoded:hex', 'decode-depth:2']`. Tags follow overlapping decoded segments
through the same original-span mapping as masking; unrelated encoded text does
not tag plaintext findings, and later unrelated passes do not increase depth.
An encoded field name alone does not tag a value outside its decoded span.
Coarse percent spans can include literal text, so the tags describe segment
provenance rather than claiming every character was encoded.

Overlapping findings retain the union of encoding tags and their maximum depth
while keeping the existing span and preferred rule type. Plaintext-only findings
retain offsets and type plus configured rule metadata. Without configured rule
tags, they have no `tags` field. The worker channel validates the exact configured
prefix and bounded canonical encoding suffix. Review still shows original values;
tags are not added to the popup, History or storage.
Decoded secret values are never returned as separate fields.

At most 1,000,000 decoded ASCII bytes are examined per call, including candidate
validation and nested passes. Exhausting that budget fails the complete scan;
browser sending remains blocked with the original draft intact. The existing
five-second browser worker deadline also applies. Decoding ends when no valid
candidates remain or the depth limit is reached; deeper encodings can be missed.
The JavaScript `scan` and `redact` APIs accept an optional fourth argument
`{ maxDecodeDepth: 0 }` to disable decoding for plaintext comparisons, or a depth
from 1 through 3. Browser guards use the default depth of 3. No dashboard setting,
Chrome permission, network request or dependency is added.

This is a bounded browser adaptation of the upstream
[Base64 codec](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/codec/base64.go),
[percent codec](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/codec/percent.go),
[hex codec](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/codec/hex.go)
and [original-span mapping](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/codec/segment.go).
The Base64 codec requires canonical final bits, accepts unpadded standard Base64 and padded
Base64url, and does not use upstream's likely-character prefilter. It does not
claim parity with every upstream encoding or reporting field. Tag names and
ordering follow the upstream [segment tags](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/detect/codec/segment.go).

## Preserved behavior and remaining scope

Browser submission checks use `src/scanner.js` to run the shared scanner in a
dedicated worker hosted by the extension's hidden `scan-host.html` frame. A
private transferred MessagePort carries the request and result directly between
the isolated content script and that extension origin. Results are not broadcast
through page messages. The host accepts only a supported parent origin and a
single scan, loads only the bundled worker and has no prompt storage or network
requests. Only the host HTML is web accessible; no Chrome permissions or allowed
websites are added.

The client deadline is five seconds, including frame startup; the host also
terminates its worker after five seconds. Completion, abort, errors and timeout
remove the frame, close the ports and terminate the worker. Draft changes, policy
refresh, teardown and page navigation invalidate pending work. Recognized sends
are prevented synchronously until the worker completes. A clean draft is
forwarded once through the existing website-control approval flow; detected
values use the existing review. Mask verifies the complete masked text in a
worker before changing the editor, then validates that exact text and policy
before activating Send. A timeout leaves the original draft intact. Failures
never fall back to synchronous scanning or permit an unchecked send. The
synchronous Node/library API is unchanged and has no cancellation parameter.

- Send, Edit, Mask, strict mode, History, counters, custom-field controls and all
  nine browser adapters retain their existing behavior and design.
- Saved custom names and the client-ID preference protect explicit assignments
  as described above.
- Grouped/distant-value heuristics and other retired SecretGuard detectors are not
  restored. Built-in matches use the enabled upstream expressions and keyword
  prefilters; custom fields require explicit assignments.
- Five rules remain disabled because prompt text has no filename:
  `freemius-secret-key` (`.php`), `hashicorp-tf-password` (`.tf`/`.hcl`),
  `kubernetes-secret-yaml` (`.yaml`/`.yml`), `nuget-config-password`
  (`nuget.config`) and path-only `pkcs12-file` (`.p12`/`.pfx`). Their filename
  requirements are not silently dropped.
- This does not implement file/commit scanning, other encoding formats, baselines,
  ignore fingerprints or credential validation.
- A prompt has no file path. An upstream exclusion requiring both path and line
  cannot match; path-only exclusions also do not suppress prompt text.
- Inline `gitleaks:allow` comments do not bypass protection, corresponding to the
  upstream `--ignore-gitleaks-allow` option.

## Verification

`tests/fixtures/gitleaks-generic.json` records 375 independently evaluated cases;
`tests/fixtures/gitleaks-providers.json` adds 837 cases across the ten new rules.
`tests/fixtures/gitleaks-structured.json` adds 579 private-key and JWT cases.
`tests/fixtures/gitleaks-curl.json` adds 697 cURL cases.
`tests/fixtures/gitleaks-collaboration.json` adds 1,481 Slack, Stripe and npm cases.
`tests/fixtures/gitleaks-catalog.json` adds 11,460 cases for the other 191 rules,
bringing the reference corpus to **15,429 cases**, with positive upstream
findings for every enabled rule.
The reference is the official Gitleaks **8.30.1** binary, using the pinned config,
one selected rule per case, `--max-decode-depth 0` and
`--ignore-gitleaks-allow`. Its SHA-256 was checked against the official release
checksum file. The binary is not shipped or required at runtime or in CI.

`tests/fixtures/gitleaks-base64.json` adds 36 independently evaluated decoding
cases across six rule families, both alphabets and three nesting levels, using
the same binary/config with `--max-decode-depth 3`. Tests retain plaintext
comparisons with decoding disabled where expected results depend on that flag.
`tests/base64.test.mjs` also wraps a positive ASCII reference input for each of
the 217 rules, and checks original-span mapping, cross-segment cURL findings,
custom/client-ID settings, malformed/binary input, depth and size limits,
idempotence, seeded mixtures and bounded long-input execution. Browser fixtures
exercise repeated Send/Edit/Mask attempts, counters and History on all nine
adapters, plus strict mode, decoded settings and budget exhaustion.

`tests/fixtures/gitleaks-percent.json` adds 48 independently evaluated percent
and mixed Base64/percent cases across six rule families and eight encoding paths,
using the same binary/config at depth 3. `tests/percent.test.mjs` also encodes a
positive ASCII input for every enabled rule and verifies partial assignments, URL text, unchanged
rule boundaries, invalid escapes, binary/non-ASCII escapes, literal plus signs,
UTF-16 mapping, nested limits, shared budget exhaustion and long near matches.
The routed browser fixtures cover repeated review actions on all nine adapters,
strict mode, settings and original-draft preservation on percent-budget failure.

`tests/fixtures/gitleaks-hex.json` adds 78 independently evaluated hex and mixed
Base64/percent/hex cases across six rule families and thirteen encoding paths,
using the same binary/config at depth 3. The combined reference corpus is now
**15,591 cases**. `tests/hex.test.mjs` also encodes a positive ASCII input for all
217 rules and verifies case, length/pair boundaries, original UTF-16 spans,
custom/client-ID preferences, exclusions, binary rejection, nested limits and
shared budgets. Browser fixtures exercise repeated Send/Edit/Mask on all nine
adapters, strict mode, settings and original-draft preservation on hex-budget
failure. These fixtures do not certify live-provider delivery.

The 162 Base64, percent and hex reference cases also contain independently
evaluated upstream encoding/depth tags from the same binary/config. These are
the same cases, not an additional corpus. `tests/encoding-tags.test.mjs` checks
those tags, nested and mixed depths, per-finding provenance, overlap merging,
cross-segment spans, unchanged plaintext findings, policy settings and bounded
large inputs. Worker tests reject malformed metadata and verify tag transport
alongside the original review, masking, counters and History on all nine adapters.

`tests/fixtures/gitleaks-shared-allowlists.json` adds 64 independently evaluated
cases across 16 allowlist configurations, bringing the combined reference corpus
to **15,655 cases**. The same official binary and pinned config are used with
`stdin`, `--max-decode-depth 0` and `--ignore-gitleaks-allow`. To append shared
lists, the reference runner converts the base config's legacy `[allowlist]`
header to the equivalent `[[allowlists]]`; its original criteria stay unchanged.
`tests/shared-allowlists.test.mjs` checks exact scopes, multiple/duplicate IDs,
global and per-rule composition, validation failures, decoded text, independent
catalogs, explicit custom/client protection and bounded large inputs. The 31
shared-allowlist browser fixtures use a private copy with synthetic exclusions
and verify all nine adapters, review actions, strict mode, counters, History and
blocked sends for unknown targets. The production catalog is never altered by
these fixtures.

`tests/fixtures/gitleaks-composite.json` adds 179 independently evaluated cases,
bringing the combined reference corpus to **15,834 cases**. There are 176
plaintext cases across 16 composite configurations, plus three fully encoded
Base64/hex/percent cases. The same official binary and pinned config are used,
with only synthetic rules appended and the equivalent legacy allowlist-header
conversion described above. `tests/composite.test.mjs` also checks all-ID and
duplicate-ID behavior, exact line/column boundaries, UTF-8/CRLF coordinates,
full-match versus capture starts, hidden support, keyword/dependency bypass,
entropy/exclusions, invalid metadata, original-span mapping, decoded-context
adaptation, independent custom/client/provider findings and comparison limits.
The composite browser fixtures use a private synthetic catalog to check nine
adapters, Send/Edit/Mask, strict encoded flows, primary-only review/counts,
History, unchanged incomplete composites, and failure/retry for invalid IDs
and exhausted comparison budgets. Production catalog data is never modified.

The tests compare each rule's extracted secrets to the reference and verify
UTF-16 offsets, masking, idempotence, malformed data, mixed-rule overlaps,
length/entropy boundaries, known exclusions, repeated values and large drafts.
The cURL tests cover alternative captures, quoted and unquoted user/password
pairs, header schemes and names, continuations, spacing, case, Unicode folds,
placeholder exclusions, command boundaries and repeated authentication options.
Adversarial long cURL and whole-catalog inputs run in bounded subprocesses to
catch scan hangs. The catalog cases include seeded strings, Unicode context,
JSON, repeated values, case changes, truncation, CRLF and ordinary-code negatives.
The migrated catalog also exercises 10,000 seeded assignment combinations.
`tests/custom-fields.test.mjs` checks literal field boundaries, quoting, short
values, Unicode offsets, placeholders, policy changes, overlaps, all 50 names
and bounded long-input execution. Managed-policy tests check that only the
administrator's replacement field list applies.
`tests/scanner.test.mjs` covers deadline/abort cleanup, late results, malformed
responses, exact redaction spans and independent requests. The browser worker
fixtures exercise restrictive page CSP across all nine adapters, an actually
hung worker, retry, errors, draft/policy/reload cancellation, forged page
messages and a timeout before Mask writes the draft.

`tests/browser/detection-removal.spec.mjs` exercises repeated Enter/click attempts
with Send, Edit and Mask across all nine routed provider fixtures, using
generic assignments, standalone keys, multiline private keys, JWTs and cURL
headers/user credentials, Slack/Stripe/npm and representative extended provider
formats including wrapped JWTs, plus saved custom fields. Custom-field tests
exercise Send/Edit/Mask, counters and History across all nine adapters, strict
mode, field removal, incomplete literals and the 50-field limit. Strict-mode
tests also cover repeated cURL options. Lexical
tests cover editor-state synchronization for paragraphs and line breaks,
including multiline custom values and a draft changed during masking. Cross-node replacements let the
editor handle its own text transaction before native editing. Reload tests cover
recovery without submitting old drafts.
The multiline regressions also cover Chromium's extra-BR insertion when a
replacement crosses block elements. Only an exact extra newline is corrected
through an editing transaction; rejected updates still prevent sending.
No real credentials or requests to live AI services are used.

All unit and browser suites use the current detection scope. Browser contract
samples in `tests/fixtures/gitleaks-credentials.mjs` derive their expected values
from the independent upstream reference, rather than calling the scanner to
generate expectations. Retired heuristics remain negative cases. Settings,
counters, History, strict mode, approval invalidation, duplicate-send prevention,
notice timers and 25 consecutive Send/Mask attempts on both primary adapters
remain covered. These are local browser contracts, not live-provider delivery
certification.

`tests/fixtures/gitleaks-metadata.json` adds 245 independently evaluated reference
cases: one positive scan for each of the 217 enabled rules, plus 28 synthetic
metadata configurations covering absent/empty descriptions, ordered and duplicate
tags, Unicode, reserved-looking tag values, hidden auxiliary rules and plaintext,
Base64, hex and percent inputs. These use the same checksum-verified official
Gitleaks 8.30.1 binary and pinned config as the other reference corpora. The
combined reference corpus now contains **16,079 cases**. Rule-metadata unit tests
also cover overlap selection, original/decoded merging, ownership, limits and
malformed configuration. Worker/browser fixtures verify exact metadata transport,
failure/retry, all nine adapters' Send/Edit/Mask choices and strict encoded Mask.

`tests/fixtures/gitleaks-locations.json` adds 144 official Gitleaks 8.30.1
whole-capture reference scans, retaining raw upstream coordinates alongside
independent UTF-8 byte-buffer expectations for the browser's normalized original
spans. Cases include Unicode prefixes and values, LF/CRLF/bare CR, blank lines,
multiline values, and terminated/unterminated last lines. The documented LF/end
adaptations affect 102 of these cases. The combined reference corpus contains
**16,223 cases**. Location tests also check all 217 enabled catalog examples,
the existing 162 encoded references, nested mixed codecs, overlap merging,
surrogate boundaries, metadata ownership and 20,000 findings in a long prompt.
Worker/browser fixtures check exact original coordinates, rejection and retry
for missing/altered fields, and nine-adapter Send/Edit/Mask behavior.

`tests/fixtures/gitleaks-rule-selection.json` adds 22 independent official
Gitleaks 8.30.1 stdin scans covering omitted/empty selections, one or multiple
IDs, duplicates, nonmatching rules, unknown IDs, all three codecs and composite
support selection. These bring the combined reference corpus to **16,245 cases**.
`tests/rule-selection.test.mjs` also selects every one of the 217 rules against
its existing official positive example, verifies unchanged defaults, and checks
allowlists, independent custom/client-ID protection, limits, invalid configuration
and cache isolation. Private worker tests cover concurrent selection, input
ownership, invalid/unselected responses, cleanup/retry, and default automatic
protection across all nine browser adapters. These fixtures do not certify
live-provider delivery.
