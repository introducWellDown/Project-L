from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List
import configparser
import pathlib

try:
    import tomllib  # Python 3.11+
except Exception:  # pragma: no cover
    tomllib = None


@dataclass(slots=True)
class Profile:
    """Описание профиля PyLynis"""
    name: str
    path: Optional[str]
    include_tests: List[str]
    skip_tests: List[str]


# Профиль по умолчанию
_DEF = Profile(name="default", path=None, include_tests=[], skip_tests=[])


def _parse_ini(text: str) -> Profile:
    """Разбор ini-профиля"""
    cp = configparser.ConfigParser()
    try:
        cp.read_string(text)
    except Exception:
        return _DEF
    include: list[str] = []
    skip: list[str] = []
    if cp.has_section("pylynis"):
        include = [
            x.strip()
            for x in cp.get("pylynis", "tests", fallback="").split(",")
            if x.strip()
        ]
        skip = [
            x.strip()
            for x in cp.get("pylynis", "skip", fallback="").split(",")
            if x.strip()
        ]
    return Profile(name="ini", path=None, include_tests=include, skip_tests=skip)


def _parse_toml(data: bytes) -> Profile:
    """Разбор toml-профиля"""
    if not tomllib:
        return _DEF
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except Exception:
        return _DEF
    node = doc.get("pylynis", {})
    include = node.get("tests", []) or []
    skip = node.get("skip", []) or []
    return Profile(name="toml", path=None, include_tests=list(include), skip_tests=list(skip))


def load_profile(path: Optional[str]) -> Profile:
    """Загрузка профиля из ini/toml файла, иначе возврат профиля по умолчанию"""
    if not path:
        return _DEF
    p = pathlib.Path(path)
    if not p.exists():
        return _DEF

    try:
        if p.suffix.lower() in {".ini", ".prf", ".cfg"}:
            return _parse_ini(p.read_text(encoding="utf-8"))
        if p.suffix.lower() == ".toml":
            return _parse_toml(p.read_bytes())
        # fallback: пробуем как ini
        return _parse_ini(p.read_text(encoding="utf-8"))
    except Exception:
        return _DEF
