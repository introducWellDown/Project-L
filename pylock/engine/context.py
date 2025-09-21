from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional


@dataclass(slots=True)
class Context:
    subject: str
    profile_path: Optional[str]
    env: Mapping[str, str]
    verbose: bool = False
    debug: bool = False
