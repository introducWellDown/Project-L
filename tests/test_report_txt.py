from pylock.core.types import Report, CheckResult
from pylock.reporters.txt import TXTReporter

def test_txt_reporter(tmp_path):
    rpt = Report(subject="demo", meta={}, checks=[
        CheckResult(id="X-1", title="CheckX", category="CAT", status="ok"),
        CheckResult(id="X-2", title="CheckY", category="CAT", status="fail"),
    ])
    out = tmp_path / "r.txt"
    TXTReporter().emit(rpt, output_file=str(out))
    data = out.read_text()
    assert "CAT" in data
    assert "X-1" in data
    assert "X-2" in data
