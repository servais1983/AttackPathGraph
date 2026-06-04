#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de parsing pour les fichiers XML/JSON de Metasploit.
Ce module permet d'importer les résultats de scan Metasploit dans AttackPathGraph.
"""

import json
import xml.etree.ElementTree as ET
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def load_metasploit_data(path):
    """
    Charge et parse un fichier généré par Metasploit (XML ou JSON).
    
    Args:
        path (str): Chemin vers le fichier Metasploit
        
    Returns:
        dict: Dictionnaire contenant les hôtes, vulnérabilités et leurs relations
    """
    logger.info(f"Chargement du fichier Metasploit : {path}")
    result = {
        "hosts": {},
        "vulnerabilities": {},
        "exploits": {},
        "relations": []
    }
    
    file_path = Path(path)
    
    try:
        # Déterminer le format du fichier
        if file_path.suffix.lower() == '.json':
            return _parse_metasploit_json(path, result)
        elif file_path.suffix.lower() == '.xml':
            return _parse_metasploit_xml(path, result)
        else:
            logger.error(f"Format de fichier non supporté: {file_path.suffix}")
            return result
            
    except Exception as e:
        logger.error(f"Erreur lors du traitement du fichier Metasploit: {e}")
        return result

def _parse_metasploit_json(path, result):
    """
    Parse un fichier JSON de Metasploit.
    
    Args:
        path (str): Chemin vers le fichier JSON
        result (dict): Dictionnaire de résultat à remplir
        
    Returns:
        dict: Dictionnaire mis à jour
    """
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        
        # Traitement des hôtes
        if 'hosts' in data:
            for host in data['hosts']:
                ip = host.get('address') or host.get('ip') or host.get('host')
                if not ip:
                    continue
                
                result["hosts"][ip] = {
                    "type": "host",
                    "ip": ip,
                    "os": host.get('os_name', ''),
                    "hostname": host.get('name', '')
                }
        
        # Traitement des vulnérabilités
        if 'vulns' in data:
            for vuln in data['vulns']:
                vuln_id = vuln.get('id') or f"msf_vuln_{len(result['vulnerabilities'])}"
                host_ip = vuln.get('host') or vuln.get('host_ip')
                
                if not host_ip:
                    continue
                
                result["vulnerabilities"][vuln_id] = {
                    "type": "vulnerability",
                    "name": vuln.get('name', 'Vulnérabilité inconnue'),
                    "info": vuln.get('info', ''),
                    "severity": float(vuln.get('severity', 0.0)) if vuln.get('severity') else 0.0
                }
                
                # Relation hôte-vulnérabilité
                result["relations"].append({
                    "source": host_ip,
                    "target": vuln_id,
                    "label": "has_vulnerability"
                })
        
        # Traitement des exploits
        if 'modules' in data or 'exploits' in data:
            modules = data.get('modules', []) or data.get('exploits', [])
            for module in modules:
                module_id = module.get('id') or f"msf_module_{len(result['exploits'])}"
                
                result["exploits"][module_id] = {
                    "type": "exploit",
                    "name": module.get('name', 'Module inconnu'),
                    "description": module.get('description', ''),
                    "rank": module.get('rank', 'normal')
                }
                
                # Relations exploit-vulnérabilité
                for vuln_ref in module.get('references', []):
                    if vuln_ref in result["vulnerabilities"]:
                        result["relations"].append({
                            "source": module_id,
                            "target": vuln_ref,
                            "label": "exploits"
                        })
        
    except json.JSONDecodeError as e:
        logger.error(f"Erreur de décodage JSON: {e}")
    
    return result

def _parse_metasploit_xml(path, result):
    """
    Parse un fichier XML de Metasploit.
    
    Args:
        path (str): Chemin vers le fichier XML
        result (dict): Dictionnaire de résultat à remplir
        
    Returns:
        dict: Dictionnaire mis à jour
    """
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        
        # Traitement des hôtes
        for host in root.findall('.//host') or root.findall('.//Host'):
            ip = None
            
            # Récupération de l'adresse IP
            addr_elem = host.find('./address') or host.find('./Address')
            if addr_elem is not None:
                ip = addr_elem.text or addr_elem.get('addr')
            
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
            hostname_elem = host.find('./hostname') or host.find('./Hostname')
            if hostname_elem is not None:
                result["hosts"][ip]["hostname"] = hostname_elem.text
            
            # Récupération du système d'exploitation si disponible
            os_elem = host.find('./os_name') or host.find('./os')
            if os_elem is not None:
                result["hosts"][ip]["os"] = os_elem.text
            
            # Traitement des services et vulnérabilités pour cet hôte
            for service in host.findall('./services/service') or host.findall('./Services/Service'):
                port = service.get('port') or service.find('./port').text if service.find('./port') else "0"
                # Création d'un nœud de service
                service_id = f"{ip}:{port}"
                
                # Relation hôte-service
                result["relations"].append({
                    "source": ip,
                    "target": service_id,
                    "label": "exposes"
                })
                
                # Traitement des vulnérabilités pour ce service
                for vuln in service.findall('./vulns/vuln') or service.findall('./Vulnerabilities/Vulnerability'):
                    vuln_id = vuln.get('id') or f"msf_vuln_{len(result['vulnerabilities'])}"
                    vuln_name = vuln.get('name') or vuln.find('./name').text if vuln.find('./name') else "Vulnérabilité inconnue"
                    
                    result["vulnerabilities"][vuln_id] = {
                        "type": "vulnerability",
                        "name": vuln_name,
                        "info": vuln.find('./info').text if vuln.find('./info') else "",
                        "severity": float(vuln.find('./severity').text) if vuln.find('./severity') else 0.0
                    }
                    
                    # Relation service-vulnérabilité
                    result["relations"].append({
                        "source": service_id,
                        "target": vuln_id,
                        "label": "has_vulnerability"
                    })
        
    except ET.ParseError as e:
        logger.error(f"Erreur lors du parsing du fichier XML Metasploit: {e}")
    
    return result
