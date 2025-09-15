from pylynis.checks.network import NETW_1000_OpenPorts
from pylynis.engine.context import Context

def test_network_ports(monkeypatch):
    ctx = Context(subject="s", profile_path=None, env={})
    chk = NETW_1000_OpenPorts()
    class FakeProc:
        returncode = 0
        stdout = "127.0.0.1:22\n"
        stderr = ""
    import pylynis.checks.network as mod
    monkeypatch.setattr(mod, "run_cmd", lambda *a, **kw: FakeProc())
    res = chk.run(ctx)
    assert res.status == "ok"
