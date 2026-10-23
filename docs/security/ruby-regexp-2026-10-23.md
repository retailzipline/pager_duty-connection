# Ruby regexp compilation assessment

Assessed on 2026-10-23 against repository commit `ce973fe4de3ae0f403b218e21bad86daee72df35`.

The development Ruby pin needs an update. The pinned Ruby 2.7.5 contains the unchecked compiler arithmetic and repeat IDs addressed by this advisory. No attacker-controlled pattern compilation path was found in this library's normal request or response processing. This is a runtime maintenance fix, not a confirmed remotely exploitable vulnerability in this gem.

## Advisory and patch evidence

[Ruby's advisory](https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/) describes memory corruption while compiling attacker-controlled regexp patterns. Matching external text against a developer-written regexp does not meet that condition. `Regexp.timeout` and pattern length limits do not reliably prevent these compiler bugs.

The CVE identifiers describe GitLab vulnerabilities. Their GitLab product version ranges are not Ruby version ranges. Ruby maps them to these underlying fixes.

| GitLab identifier | Ruby defect and patch | First fixed 3.3 | First fixed 3.4 | First fixed 4.0 |
| --- | --- | --- | --- | --- |
| CVE-2026-89078 | Parser double free after alternation, [#13332](https://github.com/ruby/ruby/pull/13332), merged as `35000ac2ed3a1829f8d193ffb23da0e44cc6fe5f`. | 3.3.13 | 3.4.12 | 4.0.0 |
| CVE-2026-93577 | Compiled-program size arithmetic overflow, [#19020](https://github.com/ruby/ruby/pull/19020), merged as `cf35145fc46bc278e0ab0003478fc4afe6564819`. | 3.3.13 | 3.4.12 | 4.0.8 |
| CVE-2026-97229 | Same underlying compiler size fix, [#19020](https://github.com/ruby/ruby/pull/19020). | 3.3.13 | 3.4.12 | 4.0.8 |
| CVE-2026-110264 | Repeat and null-check ID overflow, [#16801](https://github.com/ruby/ruby/pull/16801), merged as `493d26dcdea8b2f0ac5d28e057b401bc809e7fae`. | 3.3.13 | 3.4.12 | 4.0.9 |

The first patch keeps a temporary alternation tree until parsing succeeds. The size patch replaces overflowing products with division-based bounds and caps emitted bytecode. The ID patch rejects counters that would overflow the signed operand type.

GitLab describes authenticated code execution for the [first two CVEs](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-1-released/). It describes unauthenticated code execution for [CVE-2026-97229](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released/) and [CVE-2026-110264](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/). Those GitLab entrypoints do not exist in this outbound API client.

## The original Ruby pin

The original `.ruby-version` contains `2.7.5`. Ruby 2.7 reached [end of life on 2023-03-31](https://www.ruby-lang.org/en/downloads/branches/). The October advisory does not provide an exhaustive affected-version range for unsupported Ruby branches.

Direct comparison with the upstream patches establishes the following about the unmodified Ruby 2.7.5 source.

- [regcomp.c](https://github.com/ruby/ruby/blob/v2_7_5/regcomp.c#L985) uses unchecked `tlen * qn->lower` and related quantifier products. Its `add_opcode` has no compiled-program size cap. These are the compiler conditions addressed by #19020 for CVE-2026-93577 and CVE-2026-97229. This establishes affected source, not a demonstrated exploit on this platform.
- [regcomp.c](https://github.com/ruby/ruby/blob/v2_7_5/regcomp.c#L374) increments `num_null_check` and `num_repeat` without the new guards. [regint.h](https://github.com/ruby/ruby/blob/v2_7_5/regint.h#L671) stores their bytecode operands in `short int`. These are the conditions addressed by #16801 for CVE-2026-110264.
- CVE-2026-89078 is less certain for this exact old pin. [Ruby 2.7.5's parser](https://github.com/ruby/ruby/blob/v2_7_5/regparse.c#L6546) lacks #13332, but its token-error branch returns without the extra `onig_node_free(node)` present in [Ruby 3.3.12](https://github.com/ruby/ruby/blob/v3_3_12/regparse.c). The published oversized-quantifier trigger reaches that branch. Patch absence alone does not prove that Ruby 2.7.5 has this specific double free. Its runtime behavior was not reproduced here.

The replacement pin is `3.3.13`. Ruby identifies it as containing all fixes. Its tagged [compiler](https://github.com/ruby/ruby/blob/v3_3_13/regcomp.c) contains the size and ID guards, and its [parser](https://github.com/ruby/ruby/blob/v3_3_13/regparse.c) contains the temporary-tree ownership fix. Ruby 3.3 is the oldest supported fixed branch, which limits the runtime migration. It is in security maintenance, with expected end of life on 2027-03-31.

## Repository input paths

The gem is an outbound PagerDuty REST client. It defines no inbound HTTP service, CI configuration parser, or user-regexp feature.

- `lib/pager_duty/connection.rb:215` strips a leading slash with the fixed `/^\//` regexp. Request paths and query values are matching or serialization input, not regexp source.
- `lib/pager_duty/connection.rb:153` builds Faraday's authentication, JSON, Mashify, timestamp, error, and transport middleware. External response bodies use ordinary JSON parsing. They do not use `JSON.load` or enable JSON object additions.
- `lib/pager_duty/connection.rb:147` sends selected timestamp strings to `Time.parse` or `Time.zone.parse`. These delegate to `Date._parse`. The [Ruby date parser](https://github.com/ruby/ruby/blob/v2_7_5/ext/date/date_parse.c#L274) compiles fixed C pattern strings and matches the supplied timestamp against them.
- `lib/pager_duty/connection.rb:118` pluralizes names from the fixed `OBJECT_KEYS` list. Response keys do not become inflection rules.
- The gemspec uses fixed regexps to select package and test file names. The examples send paths and parameters, then print returned strings.

The resolved dependency sources were also inspected. Faraday encodes query data and uses URI parsers. faraday_middleware 1.2.1 calls `JSON.parse` with default options and wraps hashes through `Hashie::Mash`. Hashie preserves scalar strings. ActiveSupport's `present?` fallback compiles the constant `BLANK_RE` in another encoding, not the contents of the checked string. Default inflection rules are developer-written patterns. Custom inflections, middleware, URI parsers, or other host monkey patches remain the consuming application's responsibility.

Representative source evidence includes [Faraday's query decoder](https://github.com/lostisland/faraday/blob/v1.10.4/lib/faraday/encoders/nested_params_encoder.rb#L81), [JSON middleware](https://github.com/lostisland/faraday_middleware/blob/v1.2.1/lib/faraday_middleware/response/parse_json.rb#L12), [Mash conversion](https://github.com/hashie/hashie/blob/v5.0.0/lib/hashie/mash.rb#L381), and [ActiveSupport's whitespace fallback](https://github.com/rails/rails/blob/v6.1.7.10/activesupport/lib/active_support/core_ext/object/blank.rb#L103). Local inspection used the exact resolved versions below.

## Build and deployment scope

`Gemfile` delegates dependencies to the gemspec and adds development tools. The gemspec permits Faraday `~> 1.0`, faraday_middleware `~> 1.0`, ActiveSupport `>= 3.2, < 8.0`, and Hashie `>= 1.2`. It declares no `required_ruby_version`. `Gemfile.lock` is ignored, so there is no exact repository deployment bundle to assess.

The tracked tree has no test suite, CI workflow, container image, buildpack, or deployment manifest. `Rakefile` loads only Bundler's gem tasks. The assessment checked all tracked files with `git ls-files`, including hidden configuration files.

Changing `.ruby-version` updates development environments that honor it. It does not select the interpreter in applications importing this gem. No package Ruby requirement or dependency constraint is changed, because this investigation found no gem-specific pattern compiler to remediate. Consuming applications must check their own interpreter versions, lockfiles, customizations, and deployment configuration.

## Focused verification

Checks ran on arm64 macOS with Ruby `3.3.13`, revision `af48f08f21`, and Bundler `2.5.22`. An isolated bundle under `/tmp/pager-duty-ruby-cves-20261023` resolved the existing constraints to Faraday `1.10.6`, faraday_middleware `1.2.1`, ActiveSupport `7.2.4`, and Hashie `5.2.0`. No lockfile or dependency change was added to the repository.

- Requiring `pager_duty-connection` and constructing a connection succeeded.
- Eight focused compatibility checks passed with 33 assertions. They covered GET pagination, POST and PUT JSON and time serialization, DELETE, Token and Bearer authentication, custom URLs, timestamp and timezone conversion, malformed timestamps, and 404, 429, and 500 errors.
- A loopback HTTP request exercised the real Net::HTTP adapter. Other request checks used Faraday's test adapter. No live PagerDuty call was made.
- The string `|{1000000}` remained ordinary data in queries, request JSON, and response summaries. An invalid timestamp containing it raised `ArgumentError`.
- Observation of `Regexp.new`, `Regexp.compile`, and `Regexp.union` during loading and those checks recorded 35 calls. Their sources were fixed URI patterns and fixed I18n patterns. The hostile marker reached none of them. This observation supplements source tracing and does not cover every possible input, encoding, native compilation call, or host customization.
- Adapted upstream checks passed on Ruby 3.3.13 for invalid alternation, both nested-repeat overflow patterns, excessive repeat IDs, and excessive null-check IDs. Each case ran in a subprocess with a 30-second timeout.
- The ID checks were also run on installed Ruby 3.3.12 without matching the resulting unsafe patterns. They failed before the update and passed on 3.3.13. This comparison validates the new ID guards. It is not a runtime reproduction on Ruby 2.7.5.

```text
Ruby 3.3.12, repeat IDs and null-check IDs, each exit 1
FAIL: overflowed IDs accepted during compilation

Ruby 3.3.13, repeat IDs, exit 0
PASS: too many range repeat

Ruby 3.3.13, null-check IDs, exit 0
PASS: too many null check
```

`gem build pager_duty-connection.gemspec` succeeded. It reported existing metadata warnings about the license, open dependency ranges, and missing Ruby requirement. `bundle exec rake -T` confirmed there is no repository test task. Syntax checks and `git diff --check` also passed.

Validation scripts, the isolated lockfile, fetched advisory and patch inputs, and observation logs remain under `/tmp/pager-duty-ruby-cves-20261023` on the assessment machine. They are local investigation artifacts, not a new maintained test suite.

## Validation limits

Ruby 2.7.5 could not run through the configured mise shim because no precompiled macOS runtime was available. Its assessment relies on tagged upstream source. The very large concatenated-pattern case for the bytecode-size cap was inspected in the patch and fixed source, but not executed because it requires a large allocation.

One resolved dependency bundle and the standard Net::HTTP adapter were exercised. This does not verify every version allowed by the broad gemspec constraints, every optional Faraday adapter, or a consuming application's bundle. No deployed runtime was inspected. No gem was published, and nothing was merged or deployed.
