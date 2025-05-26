#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de parsing pour les fichiers XML d'OpenVAS.
Ce module permet d'importer les résultats de scan OpenVAS dans AttackPathGraph.
"""

import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

def load_openvas_data(path):
    """
    Charge et parse un fichier XML généré par OpenVAS.
    
    Args:
        path (str): Chemin vers le fichier XML OpenVAS
        
    Returns:
        dict: Dictionnaire contenant les hôtes, vulnérabilités et leurs relations
    """
    logger.info(f"Chargement du fichier OpenVAS : {path}")
    result = {
        "hosts": {},
        "vulnerabilities": {},
        "relations": []
    }
    
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        
        # Namespace OpenVAS
        ns = {'openvas': 'http://www.openvas.org/xml/openvas-report'}
        
        # Extraction des hôtes et vulnérabilités
        for host in root.findall('.//openvas:host', ns) or root.findall('.//host'):
            ip = None
            
            # Récupération de l'adresse IP
            ip_elem = host.find('.//openvas:ip', ns) or host.find('.//ip')
            if ip_elem is not None:
                ip = ip_elem.text
            else:
                # Essai alternatif pour récupérer l'IP
                addr_elem = host.find('.//address')
                if addr_elem is not None and addr_elem.get('addr'):
                    ip = addr_elem.get('addr')
            
            if not ip:
                continue
                
            # Ajout de l'hôte au résultat
            result["hosts"][ip] = {
                "type": "host",
                "ip": ip,
                "os": "",
                "hostname": ""
            }
            
            # Récupération du nom d'hôte si disponible
            hostname_elem = host.find('.//openvas:hostname', ns) or host.find('.//hostname')
            if hostname_elem is not None:
                result["hosts"][ip]["hostname"] = hostname_elem.text
            
            # Récupération du système d'exploitation si disponible
            os_elem = host.find('.//openvas:os', ns) or host.find('.//os')
            if os_elem is not None:
                result["hosts"][ip]["os"] = os_elem.text
        
        # Extraction des vulnérabilités
        for result_elem in root.findall('.//openvas:result', ns) or root.findall('.//result'):
            vuln_id = result_elem.get('id', f"vuln_{len(result['vulnerabilities'])}")
            
            # Récupération de l'hôte concerné
            host_ip = None
            host_elem = result_elem.find('.//openvas:host', ns) or result_elem.find('.//host')
            if host_elem is not None:
                host_ip = host_elem.text
            
            if not host_ip:
                continue
                
            # Récupération des détails de la vulnérabilité
            name_elem = result_elem.find('.//openvas:name', ns) or result_elem.find('.//name')
            threat_elem = result_elem.find('.//openvas:threat', ns) or result_elem.find('.//threat')
            severity_elem = result_elem.find('.//openvas:severity', ns) or result_elem.find('.//severity')
            
            vuln_name = name_elem.text if name_elem is not None else "Vulnérabilité inconnue"
            vuln_threat = threat_elem.text if threat_elem is not None else "Unknown"
            vuln_severity = severity_elem.text if severity_elem is not None else "0.0"
            
            # Ajout de la vulnérabilité au résultat
            result["vulnerabilities"][vuln_id] = {
                "type": "vulnerability",
                "name": vuln_name,
                "threat": vuln_threat,
                "severity": float(vuln_severity) if vuln_severity and vuln_severity.replace('.', '', 1).isdigit() else 0.0
            }
            
            # Création de la relation entre l'hôte et la vulnérabilité
            result["relations"].append({
                "source": host_ip,
                "target": vuln_id,
                "label": "has_vulnerability"
            })
    
    except ET.ParseError as e:
        logger.error(f"Erreur lors du parsing du fichier OpenVAS: {e}")
    except Exception as e:
        logger.error(f"Erreur lors du traitement du fichier OpenVAS: {e}")
    
    logger.info(f"Chargement terminé: {len(result['hosts'])} hôtes, {len(result['vulnerabilities'])} vulnérabilités")
    return result
