import subprocess
from pylock.utils.cmd import run_cmd, CommandError

def test_run_cmd_success(monkeypatch):
    def fake_run(*a, **kw):
        return subprocess.CompletedProcess(["echo","hi"], 0, stdout="hi\n", stderr="")
    monkeypatch.setattr(subprocess, "run", fake_run)
    cp = run_cmd(["echo","hi"])  # check=True default
    assert cp.stdout.strip() == "hi"

def test_run_cmd_not_found(monkeypatch):
    def fake_run(*a, **kw):
        raise FileNotFoundError("No such file or directory: 'cmd'")
    monkeypatch.setattr(subprocess, "run", fake_run)
    cp = run_cmd(["cmd"], check=False)
    assert cp.returncode == 127

def test_run_cmd_check_raises(monkeypatch):
    def fake_run(*a, **kw):
        return subprocess.CompletedProcess(["false"], 1, stdout="", stderr="boom")
    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        run_cmd(["false"], check=True)
    except CommandError as e:
        assert "Command failed" in str(e)
    else:
        raise AssertionError("CommandError not raised")
