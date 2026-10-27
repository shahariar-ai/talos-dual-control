"""Tests for authority levels, insight views and the day-close certificate."""
import pytest

from talos.authority import LEVELS, limits_for
from talos.certificate import (CertificateError, build_certificate, certificate_from_html, render_html,
                               verify_certificate, verify_certificate_html)
from talos.demo import restore, run_scenario, tamper
from talos.insight import narrate, replay_state, stopped_actions, threats_stopped
from talos.reconcile import clear_suspense, close_day, reconcile


@pytest.fixture
def closed_run(tmp_path):
    run = run_scenario(tmp_path / "d", "injection")
    report = close_day(run.gate, run.session)
    return run, report


def test_authority_levels_are_ordered_and_not_shared():
    t, s, g = (limits_for(k) for k in ("trainee", "standard", "senior"))
    assert t.risk_budget < s.risk_budget < g.risk_budget
    limits_for("trainee").risk_budget = 1
    assert limits_for("trainee").risk_budget == LEVELS["trainee"]["limits"].risk_budget
    with pytest.raises(ValueError):
        limits_for("god")


def test_trainee_gets_frozen_where_senior_does_not(tmp_path):
    tr = run_scenario(tmp_path / "t", "injection", authority="trainee")
    sr = run_scenario(tmp_path / "s", "injection", authority="senior")
    assert tr.session.teller.frozen
    assert not sr.session.teller.frozen
    assert tr.session.teller.limits.risk_budget == 30


def test_threats_stopped_groups_and_counts(closed_run):
    run, _ = closed_run
    es = run.gate.ledger.entries()
    stopped = stopped_actions(es)
    assert stopped and all(not e["executed"] for e in stopped)
    groups = threats_stopped(es)
    assert sum(g["count"] for g in groups) == len(stopped)
    assert any(g["name"] == "Secret exfiltration" for g in groups)


def test_narrate_covers_every_entry_kind(closed_run):
    run, _ = closed_run
    for e in run.gate.ledger.entries():
        n = narrate(e)
        assert n["title"] and n["tone"] in ("ok", "info", "warn", "bad", "mute")


def test_replay_state_is_monotonic(closed_run):
    run, _ = closed_run
    es = run.gate.ledger.entries()
    stopped = [replay_state(es, i)["stopped"] for i in range(1, len(es) + 1)]
    assert stopped == sorted(stopped)
    assert "src/calc.py" in replay_state(es, len(es))["files_changed"]
    assert replay_state(es, 1)["files_changed"] == []
    final = replay_state(es, len(es))
    assert final["secret_attempted"] and not final["secret_read"]  # the .env read was held, never executed


def test_certificate_requires_closed_day(tmp_path):
    run = run_scenario(tmp_path / "d", "injection")
    rep = reconcile(run.gate.ledger, run.session.id, run.gate.ws)
    with pytest.raises(CertificateError):
        build_certificate(run.gate.ledger, run.session.id, rep)


def test_certificate_roundtrip_and_verdict_follows_clearing(closed_run):
    run, report = closed_run
    ledger = run.gate.ledger
    cert = build_certificate(ledger, run.session.id, report)
    assert cert["verdict"] == "OUT OF BALANCE"
    assert verify_certificate_html(render_html(cert), ledger)[0]
    for x in report.open_exceptions:
        clear_suspense(run.gate, run.session.id, x.seq, "accepted")
    rep2 = reconcile(ledger, run.session.id, run.gate.ws)
    assert rep2.balanced
    cert2 = build_certificate(ledger, run.session.id, rep2)
    assert cert2["verdict"] == "BALANCED" and cert2["seal"] != cert["seal"]
    assert verify_certificate(cert2, ledger)[0]


def test_certificate_detects_ledger_tampering(closed_run):
    run, report = closed_run
    ledger = run.gate.ledger
    cert = build_certificate(ledger, run.session.id, report)
    held = next(a["seq"] for a in ledger.entries() if a["kind"] == "action" and a["decision"] == "held")
    tamper(ledger, held)
    ok, msg = verify_certificate(cert, ledger)
    assert not ok and "not intact" in msg
    restore(ledger)
    assert verify_certificate(cert, ledger)[0]


def test_certificate_detects_edited_data_and_edited_page(closed_run):
    run, report = closed_run
    ledger = run.gate.ledger
    cert = build_certificate(ledger, run.session.id, report)
    forged = dict(cert, verdict="BALANCED")
    assert not verify_certificate(forged, ledger)[0]
    page = render_html(cert)
    assert not verify_certificate_html(page.replace("OUT OF BALANCE", "BALANCED", 1), ledger)[0]
    assert certificate_from_html(page)["seal"] == cert["seal"]
    with pytest.raises(CertificateError):
        certificate_from_html("<html></html>")


def test_certificate_html_escapes_untrusted_text(closed_run):
    run, report = closed_run
    cert = build_certificate(run.gate.ledger, run.session.id, report)
    cert["task"] = "<script>alert(1)</script>"
    page = render_html(cert)
    assert "<script>alert(1)</script>" not in page.split('id="talos-certificate"')[0]
