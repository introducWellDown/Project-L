from __future__ import annotations

from .base import Check
from ..core.types import Finding, Severity


class CUST_11000_Template(Check):
    id = "CUST-11000"
    title = "Custom check template"
    category = "CUST"

    def run(self, ctx):
        return self.skip(notes="Custom check not implemented")


class CUST_11001_Example(Check):
    id = "CUST-11001"
    title = "Example custom check (always ok)"
    category = "CUST"

    def run(self, ctx):
        return self.ok(notes="Custom example check passed")


class CUST_11002_ExampleFail(Check):
    id = "CUST-11002"
    title = "Example custom check (always fail)"
    category = "CUST"

    def run(self, ctx):
        f = Finding(id=self.id + ":fail", description="This is an example failure", severity=Severity.SUGGESTION)
        return self.fail([f])
