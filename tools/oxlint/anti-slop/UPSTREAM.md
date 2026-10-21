# Anti-Slop Provenance

- Source: https://github.com/dmmulroy/anti-slop
- Revision: `13909c9e07590f5a85d93c62712259fe14a883f7`
- Copied from `src/` into `tools/oxlint/anti-slop/`, excluding Effect. Tests for enabled rules are included; the pnpm-specific CLI test and tests for disabled rules are omitted. The root MIT license is included.
- Generic production sources are unmodified. Preserve the nested ESLint Stylistic license and provenance when updating.
- Enabled policy lives in `../../../oxlint.config.ts`. Oxlint and `@oxlint/plugins` are pinned to matching versions.

## Project Policy

Effect rules are not installed because Concierge does not use Effect. These generic rules are intentionally not enabled:

- `no-runtime-typeof`: explicit runtime guards are valid at untrusted provider/protocol boundaries and for callable request options.
- `no-unknown-parameters` and `no-unknown-returns`: generic API and Code Mode boundaries must not pretend to know arbitrary external values.
- `no-unsafe-dictionary-type`: open JSON and JSON Schema objects are intentional in thin API adapters and protocol metadata.

Keep Zod validation for owned input contracts; these exclusions do not justify unchecked assertions or `any`. Do not enable excluded rules or replace local policy automatically during an upstream refresh. Stage updates separately, compare against this exact revision, and preserve local configuration and licenses.
