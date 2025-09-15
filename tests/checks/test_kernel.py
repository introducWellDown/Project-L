from pylynis.checks.kernel import KRNL_1000_KernelVersion
from pylynis.engine.context import Context

def test_kernel_version():
    ctx = Context(subject="s", profile_path=None, env={})
    chk = KRNL_1000_KernelVersion()
    res = chk.run(ctx)
    assert res.id == "KRNL-1000"
    assert res.status in {"ok", "fail"}
