"""Unit and integration tests for the WO-047 adjudication harness.

Tests (all pass without database or network):
1.  resolve_anchor — line 1 (first) passes.
2.  resolve_anchor — final valid line passes.
3.  resolve_anchor — line 0 → out_of_range.
4.  resolve_anchor — beyond EOF → out_of_range.
5.  resolve_anchor — blank line → blank_line.
6.  resolve_anchor — non-empty line but token absent → token_mismatch.
7.  resolve_anchor — non-empty line and token present → anchored.
8.  resolve_anchor — empty definition → missing_anchor.
9.  Multi-line span: start_line valid, span_end valid → both anchored.
10. adjudicate_file — honest findings all anchored.
11. adjudicate_file — adversarial candidates all suppressed, counter incremented.
12. adjudicate_file — suppressed AI candidates do NOT appear as validated findings.
13. adjudicate_file — has_gate_failures is False for clean deterministic run.
14. adjudicate_file — has_gate_failures is True when adversarial candidates injected.
15. adjudicate_file — AI finding always carries requires_human_review=True.
16. adjudicate_file — evidence excerpt passes secret-leak check on masked values.
17. Suppression counter resets correctly between tests.
18. Negative control: bypass anchor validation → adjudicator rejects.
19. write_adjudication_artefact writes JSON + markdown files.
20. JSON artefact includes suppressed_unanchored_total > 0 after adversarial run.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipelineshield.benchmark.adjudication import (
    AdversarialInferenceClient,
    AnchorVerdict,
    InferenceCandidate,
    NullInferenceClient,
    RejectionReason,
    adjudicate_corpus,
    adjudicate_file,
    get_suppressed_total,
    reset_suppressed_total,
    resolve_anchor,
    write_adjudication_artefact,
)
from pipelineshield.benchmark.runner import ValidatedFinding

_FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "adjudication"


# ---------------------------------------------------------------------------
# Sample definition for unit tests
# ---------------------------------------------------------------------------

_SAMPLE_LINES = [
    "name: test-workflow",           # line 1
    "on: [push]",                    # line 2
    "",                              # line 3 — blank
    "jobs:",                         # line 4
    "  build:",                      # line 5
    "    runs-on: ubuntu-latest",    # line 6
    "    steps:",                    # line 7
    "      - uses: actions/checkout@v3",   # line 8
    "      - name: Deploy",          # line 9
    "        env:",                  # line 10
    "          API_KEY: EXAMPLE_SECRET_VALUE_FOR_TESTING_PURPOSES_ONLY_ABC123",  # line 11
]

_TOTAL_LINES = len(_SAMPLE_LINES)


# ---------------------------------------------------------------------------
# 1-8. resolve_anchor boundary tests
# ---------------------------------------------------------------------------

def test_resolve_anchor_line_1_passes():
    verdict, reason, excerpt = resolve_anchor(_SAMPLE_LINES, 1)
    assert verdict == AnchorVerdict.ANCHORED
    assert reason is None
    assert "name: test-workflow" in excerpt


def test_resolve_anchor_final_line_passes():
    verdict, reason, excerpt = resolve_anchor(_SAMPLE_LINES, _TOTAL_LINES)
    assert verdict == AnchorVerdict.ANCHORED
    assert reason is None


def test_resolve_anchor_line_zero_out_of_range():
    verdict, reason, _ = resolve_anchor(_SAMPLE_LINES, 0)
    assert verdict == AnchorVerdict.REJECTED
    assert reason == RejectionReason.OUT_OF_RANGE.value


def test_resolve_anchor_beyond_eof_out_of_range():
    verdict, reason, _ = resolve_anchor(_SAMPLE_LINES, _TOTAL_LINES + 1)
    assert verdict == AnchorVerdict.REJECTED
    assert reason == RejectionReason.OUT_OF_RANGE.value


def test_resolve_anchor_blank_line():
    verdict, reason, _ = resolve_anchor(_SAMPLE_LINES, 3)  # line 3 is blank
    assert verdict == AnchorVerdict.REJECTED
    assert reason == RejectionReason.BLANK_LINE.value


def test_resolve_anchor_token_absent():
    verdict, reason, _ = resolve_anchor(
        _SAMPLE_LINES, 1, claimed_token="DEFINITELY_NOT_PRESENT_XYZ"
    )
    assert verdict == AnchorVerdict.REJECTED
    assert reason == RejectionReason.TOKEN_MISMATCH.value


def test_resolve_anchor_token_present():
    verdict, reason, excerpt = resolve_anchor(
        _SAMPLE_LINES, 11, claimed_token="EXAMPLE_"
    )
    assert verdict == AnchorVerdict.ANCHORED
    assert reason is None
    assert "EXAMPLE_" in excerpt


def test_resolve_anchor_empty_definition():
    verdict, reason, _ = resolve_anchor([], 1)
    assert verdict == AnchorVerdict.REJECTED
    assert reason == RejectionReason.MISSING_ANCHOR.value


# ---------------------------------------------------------------------------
# 9. Multi-line span
# ---------------------------------------------------------------------------

def test_multiline_span_both_lines_valid():
    start_line = 7   # "    steps:"
    span_end = 8     # "      - uses: actions/checkout@v3"
    v1, r1, e1 = resolve_anchor(_SAMPLE_LINES, start_line)
    v2, r2, e2 = resolve_anchor(_SAMPLE_LINES, span_end)
    assert v1 == AnchorVerdict.ANCHORED
    assert v2 == AnchorVerdict.ANCHORED


# ---------------------------------------------------------------------------
# 10. Honest findings all anchored
# ---------------------------------------------------------------------------

def test_adjudicate_file_honest_all_anchored():
    findings = [
        ValidatedFinding(
            control_id="sh-001",
            start_line=11,
            anchor_text=_SAMPLE_LINES[10],
            rule_id="sh-001/hardcoded-secret",
        ),
        ValidatedFinding(
            control_id="sci-001",
            start_line=8,
            anchor_text=_SAMPLE_LINES[7],
            rule_id="sci-001/unpinned-action",
        ),
    ]
    report = adjudicate_file("test.yml", _SAMPLE_LINES, findings)
    assert report.total_anchored == 2
    assert report.total_rejected == 0
    assert report.total_suppressed == 0
    assert not report.has_gate_failures
    assert report.secret_leak_detected is False


# ---------------------------------------------------------------------------
# 11-12. Adversarial candidates suppressed
# ---------------------------------------------------------------------------

def test_adversarial_candidates_all_suppressed():
    reset_suppressed_total()
    client = AdversarialInferenceClient()
    candidates = client.suggest_findings(_SAMPLE_LINES, "github_actions")
    # Each candidate is adversarial → should be suppressed
    report = adjudicate_file("test.yml", _SAMPLE_LINES, [], candidates)
    assert report.total_suppressed == len(candidates), (
        f"Expected all {len(candidates)} adversarial candidates suppressed, "
        f"got {report.total_suppressed}"
    )
    assert report.total_rejected == 0
    assert report.total_anchored == 0


def test_adversarial_candidates_not_in_validated_findings():
    client = AdversarialInferenceClient()
    candidates = client.suggest_findings(_SAMPLE_LINES, "github_actions")
    report = adjudicate_file("test.yml", _SAMPLE_LINES, [], candidates)
    # No anchored AI findings should appear in the report
    anchored_ai = [
        f for f in report.findings
        if f.source == "ai" and f.verdict == AnchorVerdict.ANCHORED
    ]
    assert len(anchored_ai) == 0, (
        f"Adversarial candidates should not be anchored: {anchored_ai}"
    )


# ---------------------------------------------------------------------------
# 13-14. has_gate_failures flag
# ---------------------------------------------------------------------------

def test_clean_deterministic_run_no_gate_failures():
    findings = [
        ValidatedFinding(
            control_id="sh-001",
            start_line=11,
            anchor_text=_SAMPLE_LINES[10],
            rule_id="sh-001/hardcoded-secret",
        ),
    ]
    report = adjudicate_file("test.yml", _SAMPLE_LINES, findings)
    assert not report.has_gate_failures


def test_adversarial_injection_suppresses_not_anchors():
    """Adversarial candidates are suppressed (good) — NOT a gate failure.

    Suppression proves the guard is exercised.  Gate failures come only from
    deterministic findings with unresolvable anchors.
    """
    reset_suppressed_total()
    client = AdversarialInferenceClient()
    candidates = client.suggest_findings(_SAMPLE_LINES, "github_actions")
    report = adjudicate_file("test.yml", _SAMPLE_LINES, [], candidates)
    # All adversarial candidates suppressed → suppression counter incremented.
    assert get_suppressed_total() > 0
    # Suppression is GOOD — no gate failure from correct suppression.
    assert not report.has_gate_failures
    assert report.total_suppressed == len(candidates)


# ---------------------------------------------------------------------------
# 15. AI findings always require human review
# ---------------------------------------------------------------------------

def test_ai_finding_always_requires_human_review():
    # Create an honest AI candidate (valid anchor, matching token)
    honest_candidate = InferenceCandidate(
        control_id="sh-001",
        start_line=11,
        rule_id="sh-001/honest-ai",
        detail="Honest AI finding",
        claimed_token="EXAMPLE_",
    )
    report = adjudicate_file("test.yml", _SAMPLE_LINES, [], [honest_candidate])
    ai_findings = [f for f in report.findings if f.source == "ai"]
    assert len(ai_findings) == 1
    assert ai_findings[0].requires_human_review is True
    assert ai_findings[0].verdict == AnchorVerdict.ANCHORED


# ---------------------------------------------------------------------------
# 16. Secret-leak assertion on evidence excerpts
# ---------------------------------------------------------------------------

def test_evidence_excerpt_masked_placeholder_passes_secret_check():
    findings = [
        ValidatedFinding(
            control_id="sh-001",
            start_line=11,
            anchor_text="          API_KEY: EXAMPLE_SECRET_VALUE_FOR_TESTING_PURPOSES_ONLY_ABC123",
            rule_id="sh-001/hardcoded-secret",
        ),
    ]
    report = adjudicate_file("test.yml", _SAMPLE_LINES, findings)
    # The EXAMPLE_ prefix should not trip the secret-leak check
    assert not report.secret_leak_detected


# ---------------------------------------------------------------------------
# 17. Suppression counter resets correctly
# ---------------------------------------------------------------------------

def test_suppression_counter_resets():
    reset_suppressed_total()
    assert get_suppressed_total() == 0
    client = AdversarialInferenceClient()
    candidates = client.suggest_findings(_SAMPLE_LINES, "github_actions")
    adjudicate_file("test.yml", _SAMPLE_LINES, [], candidates)
    after = get_suppressed_total()
    assert after > 0, "Adversarial run must increment the suppression counter"
    reset_suppressed_total()
    assert get_suppressed_total() == 0


# ---------------------------------------------------------------------------
# 18. Negative control: bypass anchor validation → adjudicator rejects
# ---------------------------------------------------------------------------

def test_negative_control_unvalidated_finding_rejected():
    """Bypass the runner's anchor validator by injecting a raw bad finding.

    The adjudicator must independently reject it (proves the gate is not vacuous).
    """
    # Directly create a ValidatedFinding with an out-of-range line number,
    # simulating a bypassed anchor validator.
    bad_finding = ValidatedFinding(
        control_id="sh-001",
        start_line=9999,  # out of range
        anchor_text="",
        rule_id="sh-001/bypassed",
    )
    report = adjudicate_file("test.yml", _SAMPLE_LINES, [bad_finding])
    assert report.total_rejected == 1
    assert report.has_gate_failures is True


def test_negative_control_harness_exits_nonzero_on_rejected():
    """corpus_adjudicate returns overall_pass=False when any finding is rejected."""
    bad_finding = ValidatedFinding(
        control_id="sh-001",
        start_line=9999,
        anchor_text="",
        rule_id="sh-001/bypassed",
    )
    file_results = [("test.yml", _SAMPLE_LINES, [bad_finding])]
    _, overall_pass = adjudicate_corpus(Path("/tmp"), file_results)
    assert overall_pass is False


# ---------------------------------------------------------------------------
# 19. write_adjudication_artefact
# ---------------------------------------------------------------------------

def test_write_adjudication_artefact_creates_files(tmp_path):
    findings = [
        ValidatedFinding(
            control_id="sh-001",
            start_line=11,
            anchor_text=_SAMPLE_LINES[10],
            rule_id="sh-001/hardcoded-secret",
        ),
    ]
    report = adjudicate_file("test.yml", _SAMPLE_LINES, findings)
    json_path, md_path = write_adjudication_artefact([report], tmp_path, git_sha="abc123")
    assert json_path.exists(), "JSON artefact must be written"
    assert md_path.exists(), "Markdown artefact must be written"


def test_write_adjudication_artefact_json_schema(tmp_path):
    report = adjudicate_file("test.yml", _SAMPLE_LINES, [])
    json_path, _ = write_adjudication_artefact([report], tmp_path, git_sha="abc123")
    data = json.loads(json_path.read_text())
    assert "schema_version" in data
    assert "overall_pass" in data
    assert "files" in data
    assert isinstance(data["files"], list)
    assert "suppressed_unanchored_total" in data


# ---------------------------------------------------------------------------
# 20. JSON artefact has suppressed_unanchored_total > 0 after adversarial run
# ---------------------------------------------------------------------------

def test_artefact_suppressed_counter_nonzero_after_adversarial(tmp_path):
    reset_suppressed_total()
    client = AdversarialInferenceClient()
    candidates = client.suggest_findings(_SAMPLE_LINES, "github_actions")
    report = adjudicate_file("test.yml", _SAMPLE_LINES, [], candidates)
    json_path, _ = write_adjudication_artefact([report], tmp_path, git_sha="adv123")
    data = json.loads(json_path.read_text())
    assert data["suppressed_unanchored_total"] > 0, (
        "Adversarial run must increment the suppressed counter in the artefact"
    )


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------

def test_adversarial_fixture_all_expected_suppressed():
    """Each case in the adversarial fixture must be suppressed by the harness."""
    fixture_path = _FIXTURE_DIR / "adversarial_inference_responses.json"
    if not fixture_path.exists():
        pytest.skip("adversarial fixture not found")

    data = json.loads(fixture_path.read_text())
    lines_for_blank = ["line one content", "line two content", "", "line four content"]

    for case in data["cases"]:
        cand = InferenceCandidate(
            control_id=case["candidate"]["control_id"],
            start_line=case["candidate"]["start_line"],
            rule_id=case["candidate"]["rule_id"],
            claimed_token=case["candidate"].get("claimed_token", ""),
        )
        report = adjudicate_file("fixture.yml", lines_for_blank, [], [cand])
        ai_findings = [f for f in report.findings if f.source == "ai"]
        assert len(ai_findings) == 1
        expected = case["expected_verdict"]
        actual = ai_findings[0].verdict.value
        assert actual == expected, (
            f"Case {case['id']}: expected verdict {expected!r}, got {actual!r}"
        )
