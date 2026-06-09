"""OpenVAS XML parser."""

import logging

from defusedxml import ElementTree as ET

logger = logging.getLogger(__name__)


def _local_name(element):
    return element.tag.rsplit("}", 1)[-1].lower()


def _first_child(element, *names):
    expected = {name.lower() for name in names}
    for child in element:
        if _local_name(child) in expected:
            return child
    return None


def _child_text(element, *names, default=""):
    child = _first_child(element, *names)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _host_address(host):
    address = _child_text(host, "ip", "address")
    if address:
        return address

    address_element = _first_child(host, "address")
    if address_element is not None:
        return address_element.get("addr", "")

    if host.text and not list(host):
        return host.text.strip()
    return ""


def _add_finding(parsed, finding, host_ip):
    if not host_ip:
        return

    vulnerability_id = finding.get(
        "id",
        f"vuln_{len(parsed['vulnerabilities'])}",
    )
    severity_text = _child_text(finding, "severity", default="0.0")
    try:
        severity = float(severity_text)
    except (TypeError, ValueError):
        severity = 0.0

    parsed["vulnerabilities"][vulnerability_id] = {
        "type": "vulnerability",
        "name": _child_text(finding, "name", default="Unknown vulnerability"),
        "threat": _child_text(finding, "threat", default="Unknown"),
        "severity": severity,
    }
    parsed["relations"].append(
        {
            "source": host_ip,
            "target": vulnerability_id,
            "label": "has_vulnerability",
        }
    )


def load_openvas_data(path):
    """Load hosts and findings from common OpenVAS XML report layouts."""
    logger.info("Loading OpenVAS file: %s", path)
    parsed = {
        "hosts": {},
        "vulnerabilities": {},
        "relations": [],
    }

    tree = ET.parse(path)
    root = tree.getroot()
    processed_findings = set()

    # Demo and some exports nest result elements under their host.
    for host in (element for element in root.iter() if _local_name(element) == "host"):
        host_ip = _host_address(host)
        if not host_ip:
            continue

        parsed["hosts"].setdefault(
            host_ip,
            {
                "type": "host",
                "ip": host_ip,
                "os": _child_text(host, "os"),
                "hostname": _child_text(host, "hostname"),
            },
        )

        for finding in (
            element for element in host.iter() if _local_name(element) == "result"
        ):
            _add_finding(parsed, finding, host_ip)
            processed_findings.add(id(finding))

    # Standard OpenVAS result lists put the target host inside each result.
    for finding in (
        element for element in root.iter() if _local_name(element) == "result"
    ):
        if id(finding) in processed_findings:
            continue

        host = _first_child(finding, "host")
        host_ip = ""
        if host is not None:
            host_ip = (host.text or "").strip() or _host_address(host)
        if host_ip:
            parsed["hosts"].setdefault(
                host_ip,
                {
                    "type": "host",
                    "ip": host_ip,
                    "os": "",
                    "hostname": "",
                },
            )
        _add_finding(parsed, finding, host_ip)

    logger.info(
        "OpenVAS load complete: %s hosts, %s vulnerabilities",
        len(parsed["hosts"]),
        len(parsed["vulnerabilities"]),
    )
    return parsed
