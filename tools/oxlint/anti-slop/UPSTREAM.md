# Anti-Slop Provenance

- Source: https://github.com/dmmulroy/anti-slop
- Revision: `13909c9e07590f5a85d93c62712259fe14a883f7`
- Copied from `src/` into `tools/oxlint/anti-slop/`, excluding Effect. All generic rule tests are included; only the pnpm-specific CLI test is omitted. The root MIT license is included.
- Generic production sources are unmodified. Preserve the nested ESLint Stylistic license and provenance when updating.
- Enabled policy lives in `../../../oxlint.config.ts`. Oxlint and `@oxlint/plugins` are pinned to matching versions.

## Project Policy

All generic rules are enabled. Effect rules are not installed because Concierge does not use Effect. Existing implementation choices and refactoring cost are not reasons to disable a rule.

Use schemas to parse fields inspected at provider/authentication boundaries, recursive JSON types for preserved native payloads, and library-owned types for JSON Schema metadata. Do not hide violations using `any`, misleading aliases, or omitted annotations.

Narrow inline exceptions must explain why the intentional behavior would be worse under the rule. Current exceptions allow `unknown` only at the shared Code Mode argument parser, provider event argument parsers, and raw sandbox values at the JSON/image serialization boundary. These are not blanket exclusions for their files or integrations. All `no-runtime-typeof`, `no-unknown-returns`, and `no-unsafe-dictionary-type` checks remain enabled without suppressions.

Stage upstream updates separately, compare against this exact revision, and preserve local configuration, documented exceptions, and licenses.
