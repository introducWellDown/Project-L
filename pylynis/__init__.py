"""pylynis: Python port of Lynis (experimental).

GPL-3.0-only. See LICENSE.
"""
from importlib.metadata import version, PackageNotFoundError

__all__ = ["__version__"]

try:
    __version__ = version("pylynis")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"
