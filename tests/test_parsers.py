from core.parsers import load_bloodhound_data
from core.parsers.metasploit_parser import load_metasploit_data
from core.parsers.openvas_parser import load_openvas_data


def test_bloodhound_parser_supports_node_metadata():
    data = load_bloodhound_data("demo/bloodhound_sample.json")

    assert data["nodes"]["domain_admin"]["admin"] is True
    assert data["relationships"][-1]["label"] == "can_escalate_to"


def test_openvas_demo_imports_findings():
    data = load_openvas_data("demo/openvas_sample.xml")

    assert len(data["hosts"]) == 2
    assert len(data["vulnerabilities"]) == 3
    assert len(data["relations"]) == 3
    assert data["vulnerabilities"]["vuln-001"]["severity"] == 8.5


def test_metasploit_xml_imports_hosts_services_and_vulnerabilities(tmp_path):
    source = tmp_path / "metasploit.xml"
    source.write_text(
        """<?xml version="1.0"?>
<MetasploitV4>
  <hosts>
    <host>
      <address>192.0.2.10</address>
      <hostname>target.example</hostname>
      <os_name>Linux</os_name>
      <vulns>
        <vuln id="msf-host-1" name="Host vulnerability">
          <severity>6.0</severity>
        </vuln>
      </vulns>
      <services>
        <service port="443" name="https">
          <vulns>
            <vuln id="msf-1" name="Test vulnerability">
              <severity>7.5</severity>
            </vuln>
          </vulns>
        </service>
      </services>
    </host>
  </hosts>
</MetasploitV4>
""",
        encoding="utf-8",
    )

    data = load_metasploit_data(source)

    assert data["hosts"]["192.0.2.10"]["hostname"] == "target.example"
    assert data["services"]["192.0.2.10:443"]["service"] == "https"
    assert data["vulnerabilities"]["msf-host-1"]["severity"] == 6.0
    assert data["vulnerabilities"]["msf-1"]["severity"] == 7.5
    assert data["relations"][-1]["label"] == "has_vulnerability"
