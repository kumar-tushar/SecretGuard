# Gitleaks rule integration

The replacement detector enables **217 of 222 default rules**, pinned to
[Gitleaks commit `5f6ec56`](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml).
The upstream MIT license is included in `extension/licenses/GITLEAKS.txt` and
copied into the unpacked build and packages.

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

## Engine behavior

`src/gitleaks-rules.js` contains the pinned expressions, the generic rule's full
1,446-entry stopword list, provider allowlists and global content exclusions.
Original Go expressions are retained for comparison. `src/core.js` compiles and
validates the data, prefilters keywords, extracts the selected capture group
(or the entire match for rules without captures), applies entropy and evaluates
secret/match/line exclusions. Findings contain only offsets and a rule ID.
When `secretGroup` is zero, extraction uses the first populated capture, falling
back to the whole match if none is populated, as in Gitleaks. Explicit groups
continue to use their configured capture.
Whole-match extraction trims leading and trailing LF delimiters, preserving
surrounding text and the upstream entropy input.

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
including upstream provider-specific client-ID rules. These CkretGuard additions
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
retain the original `{ start, end, type }` shape without a `tags` field. The
worker channel preserves and validates the bounded canonical tags. Review still
shows original values; tags are not added to the popup, History or storage.
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
- Grouped/distant-value heuristics and other retired CkretGuard detectors are not
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
