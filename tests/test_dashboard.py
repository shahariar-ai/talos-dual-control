"""Headless smoke test of the Streamlit dashboard using Streamlit's AppTest."""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "dashboard" / "app.py")


def _btn(at, label):
    return next(b for b in at.button if label in b.label)


@pytest.fixture
def at(tmp_path, monkeypatch):
    monkeypatch.setenv("TALOS_DATA", str(tmp_path / "data"))
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    a = AppTest.from_file(APP, default_timeout=60)
    a.run()
    assert not a.exception
    return a


def test_full_demo_flow(at):
    _btn(at, "Run scenario").click().run()
    assert not at.exception
    assert any("Held for human" in m.label and m.value == "1" for m in at.metric)
    # approve the held .env read from the dashboard, then close the day
    _btn(at, "Reject").click().run()
    _btn(at, "Close the day").click().run()
    assert not at.exception
    assert any("OUT OF BALANCE" in e.value for e in at.error)
    # clear both suspense items -> balanced
    for _ in range(3):
        clears = [b for b in at.button if b.label.startswith("Clear #")]
        if not clears:
            break
        clears[0].click().run()
    assert any("BALANCED" in s.value for s in at.success)


def test_tamper_flow_shows_broken_chain(at):
    _btn(at, "Run scenario").click().run()
    _btn(at, "Falsify this entry").click().run()
    assert any("BROKEN" in e.value for e in at.error)
    _btn(at, "Restore original ledger").click().run()
    assert not any("BROKEN" in e.value for e in at.error)


def test_new_tabs_render_and_replay_slider_works(at):
    _btn(at, "Run scenario").click().run()
    assert not at.exception
    labels = [t.label for t in at.tabs]
    assert {"Overview", "Replay", "End of day"} <= set(labels)
    slider = next(s for s in at.slider if s.label == "Step")
    slider.set_value(2).run()
    assert not at.exception


def test_authority_slider_changes_budget(at):
    next(s for s in at.select_slider if s.label == "Agent authority").set_value("trainee").run()
    _btn(at, "Run scenario").click().run()
    assert not at.exception
    assert at.session_state["run"].session.teller.limits.risk_budget == 30


def test_certificate_is_offered_after_close(at):
    _btn(at, "Run scenario").click().run()
    _btn(at, "Reject").click().run()
    _btn(at, "Close the day").click().run()
    assert not at.exception
    assert any("Certificate check: valid" in s.value for s in at.success)
