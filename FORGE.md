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

## WO-030: User Story: WO-030 - Enterprise DevSecOps posture dashboard with pre-aggregated queries
- **Status:** completed
- **Commit:** `590a04a`
- **Files:** 17 (+495/-1)
- **Duration:** 381ss
- **Approach:** N/A

## WO-002: User Story: WO-002 - Length-preserving secret redactor at ingestion boundary
- **Status:** completed
- **Commit:** `b75e5b7`
- **Files:** 5 (+0/-0)
- **Duration:** 1024ss
- **Approach:** Implemented a pure, framework-free analysis module with an ordered immutable pattern registry (6 explicit RedactionPattern entries + Shannon-entropy detector) and a single-pass non-overlapping masking algorithm. The redactor collects all regex spans plus high-entropy candidates, resolves overlaps by (start, registry_index) order, and applies a newline-preserving length-exact mask (_make_mask). RedactedDoc is a frozen Pydantic model with redaction_map excluded from serialisation (Field(exclude=True)). A ThreadPoolExecutor timeout guard prevents catastrophic-backtracking DoS. Structured logging emits per-pattern counts only.

## WO-010: User Story: WO-010 - Catalogue Read and Version-Creating PATCH Endpoints
- **Status:** completed
- **Commit:** `08a6a75`
- **Files:** 15 (+1370/-5)
- **Duration:** 571ss
- **Approach:** Created the full catalogue API stack: Pydantic v2 schemas with strict extra='forbid' on ChangeFields, a deny-by-default AuthzGuard with PERSONA_CAPABILITIES map, a CatalogueService that applies change ops in-memory then revalidates through CatalogueSnapshot, and a thin FastAPI router. All three writes (new version INSERT, predecessor status UPDATE via new mark_superseded method, audit event INSERT) flush inside the caller's transaction so a rollback cleans them all up. Rationale text is redacted via the WO-002 redactor before being stored in change_detail. Tests use FastAPI TestClient with dep overrides for session and actor.
