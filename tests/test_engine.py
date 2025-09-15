from pylynis.engine.auditor import Auditor

def test_auditor_runs_and_collects_results(monkeypatch):
    aud = Auditor()

    class FakeProc:
        returncode = 0
        stdout = "Sudo version 1.9.15\n"
        stderr = ""

    # Patch run_cmd used in AUTH-1000
    from pylynis.utils import cmd as cmdmod
    def fake_run_cmd(cmd, **kw):
        return FakeProc()
    monkeypatch.setattr(cmdmod, "run_cmd", fake_run_cmd)

    report = aud.run(subject="system")
    assert report.subject == "system"
    assert any(c.id == "AUTH-1000" for c in report.checks)
