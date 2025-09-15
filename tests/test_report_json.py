import json
from pylynis.core.types import Report, CheckResult
from pylynis.reporters.json import JSONReporter

def test_json_reporter(tmp_path):
    rpt = Report(subject="x", meta={}, checks=[
        CheckResult(id="T-1", title="t", category="C", status="ok")
    ])
    out = tmp_path / "r.json"
    JSONReporter().emit(rpt, output_file=str(out))
    data = json.loads(out.read_text())
    assert data["subject"] == "x"
    assert data["checks"][0]["id"] == "T-1"
