from pylock.checks.packages import PKGS_1000_Manager
from pylock.engine.context import Context

def test_pkg_manager(monkeypatch):
    ctx = Context(subject="s", profile_path=None, env={})
    chk = PKGS_1000_Manager()
    import shutil
    monkeypatch.setattr(shutil, "which", lambda x: "" if x != "apt" else "/usr/bin/apt")
    res = chk.run(ctx)
    assert res.status == "ok"
    assert "apt" in res.notes
