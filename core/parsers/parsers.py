import json
from defusedxml import ElementTree as ET


def load_nmap_data(path):
    """Load hosts and services from a Nmap XML file."""
    result = {}
    tree = ET.parse(path)
    root = tree.getroot()

    for host in root.findall("host"):
        address = host.find("address")
        if address is None or "addr" not in address.attrib:
            continue

        ip = address.attrib["addr"]
        ports = []
        for port in host.findall(".//port"):
            portid = port.attrib.get("portid")
            if not portid:
                continue

            service = port.find("service")
            service_name = service.attrib.get("name", "unknown") if service is not None else "unknown"
            ports.append((portid, service_name))

        result[ip] = ports

    return result


def load_bloodhound_data(path):
    """Load simple BloodHound-style relationships from JSON."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "nodes" in data:
        nodes = {}
        for node in data.get("nodes", []):
            node_id = node.get("id") or node.get("name")
            if not node_id:
                continue
            attrs = {key: value for key, value in node.items() if key not in {"id", "name"}}
            attrs.setdefault("type", "user")
            nodes[node_id] = attrs

        return {
            "nodes": nodes,
            "relationships": data.get("relationships", []),
        }

    result = {}
    for rel in data.get("relationships", []):
        src = rel.get("source")
        dst = rel.get("target")
        if src and dst:
            result.setdefault(src, []).append(dst)

    return result
