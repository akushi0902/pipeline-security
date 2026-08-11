# Coverage Limitations: Not Assessable Constructs

PipelineShield analyses CI/CD pipelines **locally** — no network calls, no GitLab API requests, no outbound HTTP. This means certain GitLab CI constructs cannot be fully resolved. Each unresolvable construct is recorded in `CoverageReport.unresolved` with a `kind`, `locator`, and human-readable `reason`. These are **not** scored — they are excluded from both the score numerator and denominator.

---

## GitLab CI

### `include_remote` — Remote HTTP includes

```yaml
include:
  - remote: https://example.com/ci-template.yml
```

**Why Not Assessable:** Fetching a remote URL requires an outbound HTTP request, which PipelineShield never makes. The included file's jobs and rules are unknown.

**Impact:** Any jobs or security controls defined in the remote file are invisible to the scanner. The coverage report will show the include URL as an unresolved fragment.

---

### `include_project` — Cross-project GitLab includes

```yaml
include:
  - project: my-org/ci-templates
    file: /templates/security.yml
    ref: main
```

**Why Not Assessable:** Resolving this include requires a GitLab API call to fetch the file from another project. PipelineShield makes no API calls.

**Impact:** Same as `include_remote` — jobs defined in the referenced project file are not analysed.

---

### `include_template` — GitLab built-in CI templates

```yaml
include:
  - template: SAST.gitlab-ci.yml
```

**Why Not Assessable:** GitLab built-in templates are served from the GitLab instance's template library. Without network access, the content is unavailable.

**Impact:** Security scanning jobs added via templates (SAST, DAST, Secret Detection, etc.) will not appear in the job graph.

---

### `include_component` — GitLab CI components

```yaml
include:
  - component: gitlab.com/my-org/my-component@1.0
```

**Why Not Assessable:** Resolving a component requires a GitLab API call to fetch the component catalogue entry.

**Impact:** Component-provided jobs and policies are not analysed.

---

### `include_local` — Local file includes (not co-submitted)

```yaml
include:
  - local: /ci/base.yml
```

**Why Not Assessable (currently):** Local includes are resolvable only when the referenced file is co-submitted in the same analysis batch. When a local include is encountered in isolation, the referenced file content is unavailable.

**Planned improvement:** A future work order will thread co-submitted file content through the normalizer, making local includes fully resolvable.

---

### `extends_cycle` — Circular extends chains

```yaml
.job-a:
  extends: .job-b
.job-b:
  extends: .job-a
```

**Why Not Assessable:** A circular extends dependency cannot be resolved without infinite recursion. Cycle detection (DFS with white/gray/black colouring) identifies all jobs in a cycle.

**Impact:** All jobs participating in a cycle pass through unmodified — their merged configuration is whatever was declared directly on the job node, without any parent fields applied.

---

### `extends_missing` — Extends referencing an undefined parent

```yaml
real-job:
  extends: .undefined-template
  script: [echo hi]
```

**Why Not Assessable:** The referenced parent job does not exist in the same file, and without include resolution (see above), it cannot be fetched.

**Impact:** The job is still emitted, but without any fields from the missing parent. The coverage report records the missing parent name.

---

### `reference_unresolvable` — `!reference` pointing to a missing key

```yaml
my-job:
  script:
    - !reference [.missing-job, script]
```

**Why Not Assessable:** If the referenced job or key does not exist in the document, the `!reference` cannot be resolved. The placeholder string `[!reference [...]]` is substituted in the script text.

**Impact:** The step's `run` field contains a placeholder. Secret-ref scanning and rule analysis of that step are degraded.

---

### `stages_inferred` — No `stages:` key in the document

```yaml
# No top-level stages: key
build-job:
  stage: build
  script: [make]
```

**Why informational:** When `stages:` is absent GitLab applies its built-in default order: `.pre`, `build`, `test`, `deploy`, `.post`. PipelineShield infers this order but records it as a coverage note so analysts know the ordering was not declared explicitly.

**Impact:** Stage-order-dependent analysis may not reflect the intent of the pipeline author. This is a lower-severity limitation than the others.

---

## GitHub Actions

GitHub Actions normalizer limitations are documented separately. The local-only constraint applies equally: `${{ secrets.* }}` expressions that reference organisation-level or environment-scoped secrets are extracted as `SecretRef` objects but their values are never fetched.

---

## Scoring impact

| Kind | Excluded from denominator? |
|------|---------------------------|
| `include_remote` | Yes |
| `include_project` | Yes |
| `include_template` | Yes |
| `include_component` | Yes |
| `include_local` (not co-submitted) | Yes |
| `extends_cycle` | Yes (cyclic jobs) |
| `extends_missing` | Yes (affected jobs) |
| `reference_unresolvable` | Yes (affected steps) |
| `stages_inferred` | No — informational only |

Constructs marked Not Assessable are **never** counted as Present or Missing. A score of 0.85 with five unresolved fragments means "85% of what could be assessed passed; five constructs were outside the analysis scope."
