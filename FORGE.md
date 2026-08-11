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

## WO-036: User Story: WO-036 - OIDC PKCE login with server-side Redis session lifecycle
- **Status:** completed
- **Commit:** `bc377a5`
- **Files:** 15 (+0/-0)
- **Duration:** 980ss
- **Approach:** Implemented the full backend OIDC PKCE authentication stack. AuthConfig uses pydantic-settings and fails closed if any required secret (oidc_issuer, oidc_client_id, oidc_client_secret, oidc_redirect_uri, redis_url) is absent. RedisSessionStore stores opaque session IDs as Redis hashes with sliding EXPIRE on every read and application-code absolute-lifetime enforcement. RedisLoginStateStore keeps OIDC state params (nonce, code_challenge) for 5 minutes with atomic single-use pop (replay protection). AuthModule orchestrates begin_login (state/nonce generation, PKCE challenge validation, IdP URL build), complete_callback (state pop, S256 server-side PKCE verification, code exchange via httpx, id_token verification via PyJWT+JWKS, JIT app_user upsert, role_binding resolution, session creation, audit events), resolve_session (sliding TTL refresh), and terminate_session. The thin AuthRouter delegates everything to AuthModule, sets httpOnly/Secure/SameSite=Lax cookies, and maps errors to RFC 7807 structured bodies. Migration 0004 adds idp_subject (unique) and last_login_at to app_user with an explicit comment forbidding password columns.

## WO-038: User Story: WO-038 - Append-only audit event store with completeness enforcement
- **Status:** completed
- **Commit:** `9cd6497`
- **Files:** 15 (+1599/-20)
- **Duration:** 622ss
- **Approach:** Implemented structural audit immutability and completeness enforcement. Migration 0005 adds actor_user_id, actor_reference, workspace_id, source_ip_masked, user_agent_hash columns to audit_event, installs BEFORE UPDATE OR DELETE triggers (PostgreSQL PL/pgSQL RAISE EXCEPTION + SQLite RAISE(ABORT)) as defence against grant drift, adds query indexes, and adds a partial index on pipeline_definition for the purge worker. ContentGuard runs in reject mode — scans change_detail for secret patterns (GitHub PAT, AWS key, JWT, PEM, key=value, high-entropy) and raises AuditContentViolation with field path but never the value; oversized payloads are truncated with _truncated marker. AuditWriter is the single write path that runs the content guard and appends through AuditRepository. AuditRepository gained cursor-paginated list_scoped with workspace scoping and full filter support. AuditRouter exposes GET /api/v1/audit-events guarded by audit:read (devsecops_engineer, appsec_lead); no mutating endpoints exist, verified by OpenAPI spec test. Tests cover all patterns, nested scanning, entropy detection, truncation, immutability triggers, single-writer static analysis, repository surface, router authorization, and completeness registry.

## WO-045: User Story: WO-045 - Build Seeded Benchmark Corpus With Ground-Truth Manifest
- **Status:** completed
- **Commit:** `85c649e`
- **Files:** 16 (+0/-0)
- **Duration:** 766ss
- **Approach:** N/A

## WO-003: User Story: WO-003 - Synchronous analysis ingestion endpoint with bounded payloads
- **Status:** completed
- **Commit:** `0b7ab1e`
- **Files:** 1 (+0/-0)
- **Duration:** 685ss
- **Approach:** N/A

## WO-011: User Story: WO-011 - Immutable Audit Trail Writer and Query Endpoint
- **Status:** completed
- **Commit:** `5b78151`
- **Files:** 8 (+983/-5)
- **Duration:** 816ss
- **Approach:** N/A

## WO-013: User Story: WO-013 - Pin Analyses to Catalogue Version for Reproducible Scoring
- **Status:** completed
- **Commit:** `888c2a1`
- **Files:** 8 (+0/-0)
- **Duration:** 819ss
- **Approach:** Implemented reproducible catalogue-pinned scoring via a pure ScoringEngine service injected with an immutable CatalogueSnapshot frozen at request start. Migration 0007 adds a composite index on (catalogue_version_id, created_at DESC). The ScoringEngine uses stable sorted iteration (sorted by category.id, control.id) to guarantee determinism; zero-denominator (all categories fully-NA) returns an unscorable result with no ZeroDivisionError. AnalysisOrchestrator resolves the active catalogue snapshot exactly once, passes catalogue_version_id to _persist, and includes it in AnalysisResponse.

## WO-037: User Story: WO-037 - Deny-by-default AuthzGuard with three-layer persona enforcement
- **Status:** completed
- **Commit:** `11d0f84`
- **Files:** 1 (+0/-0)
- **Duration:** 609ss
- **Approach:** N/A

## WO-040: User Story: WO-040 - Automated 90-Day Retention Purge Worker With Receipts
- **Status:** completed
- **Commit:** `5634e1a`
- **Files:** 13 (+1929/-1)
- **Duration:** 666ss
- **Approach:** Implemented WO-040 as a layered set of components: (1) Alembic migration 0009 adds purge_due_at + retention_class to pipeline_definition and status + error_detail to purge_receipt using batch_alter_table for SQLite/PostgreSQL compatibility. (2) PurgeRepository abstract interface + SQLAlchemyPurgeRepository implementation in persistence/repositories/purge.py handles advisory lock acquisition, due-definition selection (purge_due_at <= now, retention_class != 'sample'), FK-safe bulk deletes via delete() statements (generated_draft → remediation → finding → pipeline_definition → analysis), post-delete absence verification, receipt insertion, and SLA breach counting. (3) RetentionWorker in platform/retention/ is a framework-free class injected with PurgeRepository + AuditWriter; each batch runs in its own transaction, inserts one purge_receipt + one audit_event (action=retention.purge, actor_id=system:retention_worker), handles verification failures as status=failed receipts, and continues to subsequent batches on any per-batch error. (4) purge_receipt_builder.py computes SHA-256 digests over a strictly allowlisted manifest (ids, counts, timestamps only — no content). (5) ReconciliationService generates SLA breach counts. (6) CLI entry point at platform/retention/cli.py with --dry-run and --batch-size flags.
