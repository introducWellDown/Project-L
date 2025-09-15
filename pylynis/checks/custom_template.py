from __future__ import annotations
from .base import Check
from ..core.types import Finding, Severity

class CUST_11001_Example(Check):
    id="CUST-11001"; title="Example custom check (always ok)"; category="CUST"
    def run(self, ctx):
        return self.ok(notes="Custom example check passed")
