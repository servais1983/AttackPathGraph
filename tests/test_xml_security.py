import pytest
from defusedxml.common import DefusedXmlException

from core.parsers import load_nmap_data


def test_nmap_parser_rejects_xml_entity_expansion(tmp_path):
    malicious_xml = tmp_path / "malicious.xml"
    malicious_xml.write_text(
        """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<nmaprun><host><address addr="&lol2;"/></host></nmaprun>
""",
        encoding="utf-8",
    )

    with pytest.raises(DefusedXmlException):
        load_nmap_data(malicious_xml)
