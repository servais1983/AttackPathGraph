"""Parser entry points for AttackPathGraph."""

from .parsers import load_bloodhound_data, load_nmap_data

__all__ = ["load_bloodhound_data", "load_nmap_data"]
