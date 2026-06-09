"""Metasploit JSON and XML parser."""

import json
import logging
from pathlib import Path

from defusedxml import ElementTree as ET

logger = logging.getLogger(__name__)


def _empty_result():
    return {
        "hosts": {},
        "services": {},
        "vulnerabilities": {},
        "exploits": {},
        "relations": [],
    }


def _first_child(element, *names):
    expected = {name.lower() for name in names}
    for child in element:
        if child.tag.rsplit("}", 1)[-1].lower() in expected:
            return child
    return None


def _child_text(element, *names, default=""):
    child = _first_child(element, *names)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _severity(element):
    try:
        return float(_child_text(element, "severity", default="0.0"))
    except (TypeError, ValueError):
        return 0.0


def _add_xml_vulnerability(parsed, vulnerability, source_id):
    vulnerability_id = vulnerability.get(
        "id",
        f"msf_vuln_{len(parsed['vulnerabilities'])}",
    )
    parsed["vulnerabilities"][vulnerability_id] = {
        "type": "vulnerability",
        "name": vulnerability.get("name")
        or _child_text(
            vulnerability,
            "name",
            default="Unknown vulnerability",
        ),
        "info": _child_text(vulnerability, "info"),
        "severity": _severity(vulnerability),
    }
    parsed["relations"].append(
        {
            "source": source_id,
            "target": vulnerability_id,
            "label": "has_vulnerability",
        }
    )


def load_metasploit_data(path):
    """Load a Metasploit JSON or XML export."""
    logger.info("Loading Metasploit file: %s", path)
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return _parse_metasploit_json(path)
    if suffix == ".xml":
        return _parse_metasploit_xml(path)
    raise ValueError(f"Unsupported Metasploit file format: {suffix}")


def _parse_metasploit_json(path):
    parsed = _empty_result()
    with open(path, "r", encoding="utf-8") as source:
        data = json.load(source)

    for host in data.get("hosts", []):
        host_ip = host.get("address") or host.get("ip") or host.get("host")
        if not host_ip:
            continue
        parsed["hosts"][host_ip] = {
            "type": "host",
            "ip": host_ip,
            "os": host.get("os_name", ""),
            "hostname": host.get("name", ""),
        }

    for vulnerability in data.get("vulns", []):
        host_ip = vulnerability.get("host") or vulnerability.get("host_ip")
        if not host_ip:
            continue
        vulnerability_id = vulnerability.get(
            "id",
            f"msf_vuln_{len(parsed['vulnerabilities'])}",
        )
        try:
            severity = float(vulnerability.get("severity") or 0.0)
        except (TypeError, ValueError):
            severity = 0.0
        parsed["vulnerabilities"][vulnerability_id] = {
            "type": "vulnerability",
            "name": vulnerability.get("name", "Unknown vulnerability"),
            "info": vulnerability.get("info", ""),
            "severity": severity,
        }
        parsed["relations"].append(
            {
                "source": host_ip,
                "target": vulnerability_id,
                "label": "has_vulnerability",
            }
        )

    modules = data.get("modules", []) or data.get("exploits", [])
    for module in modules:
        module_id = module.get("id") or f"msf_module_{len(parsed['exploits'])}"
        parsed["exploits"][module_id] = {
            "type": "exploit",
            "name": module.get("name", "Unknown module"),
            "description": module.get("description", ""),
            "rank": module.get("rank", "normal"),
        }
        for vulnerability_id in module.get("references", []):
            if vulnerability_id in parsed["vulnerabilities"]:
                parsed["relations"].append(
                    {
                        "source": module_id,
                        "target": vulnerability_id,
                        "label": "exploits",
                    }
                )

    return parsed


def _parse_metasploit_xml(path):
    parsed = _empty_result()
    root = ET.parse(path).getroot()
    hosts = root.findall(".//host") + root.findall(".//Host")

    for host in hosts:
        address_element = _first_child(host, "address")
        host_ip = _child_text(host, "address")
        if not host_ip and address_element is not None:
            host_ip = address_element.get("addr", "")
        if not host_ip:
            continue

        parsed["hosts"][host_ip] = {
            "type": "host",
            "ip": host_ip,
            "os": _child_text(host, "os_name", "os"),
            "hostname": _child_text(host, "hostname", "name"),
        }

        host_vulnerabilities = (
            host.findall("./vulns/vuln")
            + host.findall("./Vulnerabilities/Vulnerability")
        )
        for vulnerability in host_vulnerabilities:
            _add_xml_vulnerability(parsed, vulnerability, host_ip)

        services = (
            host.findall("./services/service")
            + host.findall("./Services/Service")
        )
        for service in services:
            port = service.get("port") or _child_text(service, "port", default="0")
            service_id = f"{host_ip}:{port}"
            parsed["services"][service_id] = {
                "type": "service",
                "port": port,
                "service": service.get("name")
                or _child_text(service, "name", default="unknown"),
            }
            parsed["relations"].append(
                {
                    "source": host_ip,
                    "target": service_id,
                    "label": "exposes",
                }
            )

            vulnerabilities = (
                service.findall("./vulns/vuln")
                + service.findall("./Vulnerabilities/Vulnerability")
            )
            for vulnerability in vulnerabilities:
                _add_xml_vulnerability(parsed, vulnerability, service_id)

    return parsed
