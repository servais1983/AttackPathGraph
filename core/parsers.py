"""Backward-compatible parser imports.

The parser implementation lives in ``core.parsers`` as a package. This module
is kept for older imports that referenced ``core.parsers.py`` directly.
"""

from core.parsers.parsers import load_bloodhound_data, load_nmap_data

__all__ = ["load_bloodhound_data", "load_nmap_data"]
