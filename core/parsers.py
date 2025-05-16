import xml.etree.ElementTree as ET
import json

def load_nmap_data(path):
    print(f"[*] Chargement du fichier Nmap : {path}")
    result = {}
    tree = ET.parse(path)
    root = tree.getroot()

    for host in root.findall("host"):
        ip = host.find("address").attrib["addr"]
        ports = []
        for port in host.findall(".//port"):
            portid = port.attrib["portid"]
            service = port.find("service")
            service_name = service.attrib.get("name", "unknown") if service is not None else "unknown"
            ports.append((portid, service_name))
        result[ip] = ports

    return result

def load_bloodhound_data(path):
    print(f"[*] Chargement du fichier BloodHound : {path}")
    with open(path, "r") as f:
        data = json.load(f)
      
    result = {}
    for rel in data.get("relationships", []):
        src = rel.get("source")
        dst = rel.get("target")
        if src and dst:
            result.setdefault(src, []).append(dst)

    return result