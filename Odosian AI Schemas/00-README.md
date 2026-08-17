# Odosian AI Result & Query-Language Schemas

Ground-truth reference for every JSON shape Odosian's AI pipeline produces, pulled directly from the live source code (not inferred). Each file below is one distinct case, in `.jsonc` format (JSON with `//` comments) so it's readable on its own — strip the comments and it's valid JSON.

## Result-showing cases (what happens after each user action)

| File | Endpoint | What it is |
|---|---|---|
| `01-analyze.jsonc` | `POST /api/analysis/analyze` | Score a rule or raw query: 0–100, letter grade, findings, suggestions, evasion risks, MITRE mappings |
| `02-post-enhance.jsonc` | `POST /api/analysis/analyze` | Same endpoint as Analyze, re-validating a freshly-enhanced query |
| `03-enhance.jsonc` | `POST /api/analysis/enhance` | AI rewrite of a rule's query + metadata (preview only, not yet saved) |
| `04-apply-enhancement.jsonc` | `POST /api/rules/[id]/apply-enhancement` | Commits an Enhance result onto the actual rule |
| `05-generate.jsonc` | `POST /api/analysis/generate` | Draft a brand-new rule from a text description |
| `06-simulate.jsonc` | `POST /api/rules/[id]/simulate` | AI-generated manual attack-execution plan to validate a rule |
| `07-batch-create.jsonc` | `POST /api/analysis/batch` | Start a bulk AI operation across many rules |
| `08-batch-list.jsonc` | `GET /api/analysis/batch` | List all batch runs |
| `09-batch-detail.jsonc` | `GET /api/analysis/batch/[id]` | One batch run, every item's outcome |
| `10-batch-review-get.jsonc` | `GET /api/analysis/batch/[id]/review` | Proposed enhancements in an enhance-batch, pending review |
| `11-batch-review-post.jsonc` | `POST /api/analysis/batch/[id]/review` | Bulk-apply selected batch enhancements |
| `12-deployments-list.jsonc` | `GET /api/audit/deployments` | Elastic push/pull history (derived from audit log, no dedicated table) |
| `13-push-to-elastic.jsonc` | `POST /api/rules/[id]/push-elastic` | Direct result of one deploy/update-in-Elastic action |

## Input formatter reference (how queries/fields are handled)

| File | Covers |
|---|---|
| `14-query-languages.jsonc` | KQL / EQL / Lucene / ES\|QL — storage value, display label, Elastic mapping, formatting rules |
| `15-rule-types.jsonc` | query / eql / threshold / new_terms / machine_learning / indicator_match — Elastic type mapping |
| `16-related-fields.jsonc` | The `index` vs `indexPatterns` gotcha, and how `requiredFields` is auto-derived from a query |
| `17-validation-schemas.jsonc` | Every Zod validation rule (max lengths, regex, strict vs. loose enums) |

## Two things worth knowing before you build against these

1. **`newRiskScore` in Enhance results isn't guaranteed to be a real JSON number.** Some model/gateway combos emit it as a quoted string. Coerce with `Number()` and check `Number.isFinite()` before trusting it.
2. **`index` (on the saved Rule) is a single comma-separated string; `indexPatterns` (in AI results) is an array.** They are not interchangeable — join the array before writing it to `index`.
