# Forge Implementation Log

| Field | Value |
|-------|-------|
| Project | 6172f887-3aab-4aac-93a9-955463ad895e |
| Branch | forge/pipeline-shield-ai-ci-cd-secur-d374f19a-run5-51wo |
| Started | 2026-08-11T11:57:55Z |

---

## WO-001: User Story: WO-001 - Baseline PostgreSQL schema and least-privilege migrations
- **Status:** completed
- **Commit:** `a8b9bae`
- **Files:** 7 (+68/-30)
- **Duration:** 825ss
- **Approach:** The greenfield pipelineshield-api scaffold was already present with all twelve SQLAlchemy 2.0 models, the Alembic baseline migration, repository interfaces/implementations, KeyProvider envelope encryption, integration tests, and seed fixture. The implementation required fixing three SQLAlchemy 2.0 compatibility issues that would have caused test failures: (1) removed the deprecated autocommit=False parameter from sessionmaker in db.py, (2) fixed alembic/env.py to honour a URL already set programmatically (e.g. by the integration test fixture) rather than always overwriting it with DATABASE_URL from the OS environment, and (3) updated the unit test session fixture to use SQLAlchemy 2.0 style with StaticPool and Session(engine) rollback isolation instead of the connection-level bind pattern. Also cleaned up unused imports in audit_event.py.

## WO-009: User Story: WO-009 - Versioned Immutable Control Catalogue Schema and Seed
- **Status:** completed
- **Commit:** `3a65bca`
- **Files:** 20 (+1816/-58)
- **Duration:** 1199ss
- **Approach:** Implemented the versioned immutable control catalogue as an append-only SQLAlchemy 2.0 model with a dialect-aware DialectJSON type (JSONB on PostgreSQL, JSON on SQLite). Added a forward-only Alembic 0002 migration using batch_alter_table for cross-dialect compatibility that renames the scaffold columns (version_number→version, description→change_notes, controls→snapshot) and adds status, grade_bands, created_by (FK app_user), and content_checksum. Defined full Pydantic v2 CatalogueSnapshot schemas with model_validators for weight totals, unique IDs, severity enum, and grade band coverage 0-100. Implemented CatalogueRepository (abstract + SQLAlchemy) with get_active, get_by_version, list_versions, and create_version (INSERT-only, raises CatalogueVersionConflictError on duplicate). Added an idempotent seed routine that validates the committed catalogue_v1.json fixture before inserting.

## WO-019: User Story: WO-019 - Seeded Corpus Detection Benchmark Harness With Release Gate
- **Status:** completed
- **Commit:** `a4e6227`
- **Files:** 28 (+2701/-0)
- **Duration:** 1462ss
- **Approach:** N/A

## WO-020: User Story: WO-020 - Deterministic weighted scoring engine with versioned catalogue
- **Status:** completed
- **Commit:** `1de657c`
- **Files:** 30 (+1657/-0)
- **Duration:** 497ss
- **Approach:** N/A

## WO-042: User Story: WO-042 - Governance Console For Audit, Retention And Exports
- **Status:** completed
- **Commit:** `9f96073`
- **Files:** 42 (+2648/-0)
- **Duration:** 854ss
- **Approach:** N/A

## WO-045: User Story: WO-045 - Build Seeded Benchmark Corpus With Ground-Truth Manifest
- **Status:** completed
- **Commit:** `231c5f4`
- **Files:** 24 (+0/-0)
- **Duration:** 941ss
- **Approach:** Authored 15 fully synthetic pipeline definitions (6 GitHub Actions, 5 GitLab CI, 4 Jenkins) in insecure/partial/hardened/not-assessable variants. Created a new GroundTruthManifest Pydantic v2 schema in ground_truth.py with SeededGap (expected_status, rationale), NegativeExpectation (for false-positive measurement), and UnassessableFragment models. Wrote a top-level ground_truth.yaml covering all 15 files with 57 seeded gaps, 48 negative expectations, and 3 NA fragments. Updated tests/fixtures/__init__.py with cached load_ground_truth() and load_corpus() helpers. All credential-shaped literals use the EXAMPLE_ prefix; all files are under 500 lines.
