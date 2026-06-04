#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'intégration MITRE ATT&CK pour AttackPathGraph.
Ce module permet de mapper les techniques d'attaque identifiées aux techniques MITRE ATT&CK.
"""

import json
import logging
import os
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

class MitreAttackIntegration:
    """
    Classe pour l'intégration avec le framework MITRE ATT&CK.
    """
    
    def __init__(self, cache_dir=None):
        """
        Initialise l'intégration MITRE ATT&CK.
        
        Args:
            cache_dir (str, optional): Répertoire pour le cache des données MITRE ATT&CK
        """
        self.cache_dir = cache_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'cache')
        self.techniques = {}
        self.tactics = {}
        self.mitigations = {}
        self.groups = {}
        self.software = {}
        self._stix_to_technique = {}
        self._stix_to_mitigation = {}
        self._stix_to_group = {}
        self._stix_to_software = {}
        
        # Créer le répertoire de cache s'il n'existe pas
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Charger les données MITRE ATT&CK
        self._load_attack_data()
    
    def _load_attack_data(self):
        """
        Charge les données MITRE ATT&CK depuis le cache ou l'API.
        """
        cache_file = os.path.join(self.cache_dir, 'mitre_attack_data.json')
        
        # Vérifier si le cache existe et est récent (moins de 30 jours)
        if os.path.exists(cache_file):
            file_age = datetime.now().timestamp() - os.path.getmtime(cache_file)
            if file_age < 30 * 24 * 60 * 60:  # 30 jours en secondes
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        self.techniques = data.get('techniques', {})
                        self.tactics = data.get('tactics', {})
                        self.mitigations = data.get('mitigations', {})
                        self.groups = data.get('groups', {})
                        self.software = data.get('software', {})
                        logger.info("Données MITRE ATT&CK chargées depuis le cache")
                        return
                except Exception as e:
                    logger.warning(f"Erreur lors du chargement du cache MITRE ATT&CK: {e}")
        
        # Si le cache n'existe pas ou est trop ancien, télécharger les données
        try:
            self._download_attack_data()
            
            # Sauvegarder les données dans le cache
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'techniques': self.techniques,
                    'tactics': self.tactics,
                    'mitigations': self.mitigations,
                    'groups': self.groups,
                    'software': self.software
                }, f, indent=2)
            
            logger.info("Données MITRE ATT&CK téléchargées et mises en cache")
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement des données MITRE ATT&CK: {e}")
            
            # Essayer de charger un cache existant même s'il est ancien
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        self.techniques = data.get('techniques', {})
                        self.tactics = data.get('tactics', {})
                        self.mitigations = data.get('mitigations', {})
                        self.groups = data.get('groups', {})
                        self.software = data.get('software', {})
                    logger.info("Données MITRE ATT&CK chargées depuis le cache (ancien)")
                except Exception as e:
                    logger.error(f"Erreur lors du chargement du cache MITRE ATT&CK: {e}")
    
    def _download_attack_data(self):
        """
        Télécharge les données MITRE ATT&CK depuis l'API.
        """
        # URL de l'API MITRE ATT&CK
        base_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        try:
            # Télécharger les données
            response = requests.get(base_url, timeout=30)
            response.raise_for_status()
            
            # Analyser les données
            data = response.json()
            
            # Extraire les techniques, tactiques, mitigations, groupes et logiciels
            for obj in data.get('objects', []):
                obj_type = obj.get('type')
                obj_id = obj.get('id')
                
                if not obj_id:
                    continue
                
                if obj_type == 'attack-pattern':
                    # Technique
                    technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    if technique_id.startswith('T'):
                        self.techniques[technique_id] = {
                            'id': technique_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'tactics': [],
                            'mitigations': []
                        }
                        self._stix_to_technique[obj_id] = technique_id
                        
                        # Associer les tactiques
                        for kill_chain_phase in obj.get('kill_chain_phases', []):
                            phase_name = kill_chain_phase.get('phase_name')
                            if phase_name:
                                self.techniques[technique_id]['tactics'].append(phase_name)
                
                elif obj_type == 'x-mitre-tactic':
                    # Tactique
                    tactic_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    if tactic_id.startswith('TA'):
                        self.tactics[tactic_id] = {
                            'id': tactic_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', '')
                        }
                
                elif obj_type == 'course-of-action':
                    # Mitigation
                    mitigation_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    if mitigation_id.startswith('M'):
                        self.mitigations[mitigation_id] = {
                            'id': mitigation_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', '')
                        }
                        self._stix_to_mitigation[obj_id] = mitigation_id
                
                elif obj_type == 'intrusion-set':
                    # Groupe
                    group_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    if group_id.startswith('G'):
                        self.groups[group_id] = {
                            'id': group_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'techniques': []
                        }
                        self._stix_to_group[obj_id] = group_id
                
                elif obj_type == 'malware' or obj_type == 'tool':
                    # Logiciel
                    software_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    if software_id.startswith('S'):
                        self.software[software_id] = {
                            'id': software_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'type': obj_type,
                            'techniques': []
                        }
                        self._stix_to_software[obj_id] = software_id
            
            # Associer les relations
            for obj in data.get('objects', []):
                obj_type = obj.get('type')
                
                if obj_type == 'relationship':
                    source_ref = obj.get('source_ref')
                    target_ref = obj.get('target_ref')
                    relationship_type = obj.get('relationship_type')
                    
                    if relationship_type == 'mitigates':
                        mitigation_id = self._stix_to_mitigation.get(source_ref)
                        technique_id = self._stix_to_technique.get(target_ref)
                        if mitigation_id and technique_id:
                            self.techniques[technique_id]['mitigations'].append(mitigation_id)
                    
                    elif relationship_type == 'uses':
                        # Relation groupe/logiciel -> technique
                        technique_id = self._stix_to_technique.get(target_ref)
                        group_id = self._stix_to_group.get(source_ref)
                        if group_id and technique_id:
                            self.groups[group_id]['techniques'].append(technique_id)
                        
                        software_id = self._stix_to_software.get(source_ref)
                        if software_id and technique_id:
                            self.software[software_id]['techniques'].append(technique_id)
        
        except requests.RequestException as e:
            logger.error(f"Erreur lors de la requête MITRE ATT&CK: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Erreur lors du décodage JSON MITRE ATT&CK: {e}")
            raise
        except Exception as e:
            logger.error(f"Erreur inattendue lors du téléchargement MITRE ATT&CK: {e}")
            raise
    
    def map_vulnerability_to_technique(self, vulnerability):
        """
        Mappe une vulnérabilité à une technique MITRE ATT&CK.
        
        Args:
            vulnerability (dict): Données de la vulnérabilité
            
        Returns:
            list: Liste des techniques MITRE ATT&CK correspondantes
        """
        mapped_techniques = []
        
        # Mots-clés pour le mapping
        keywords = {
            'Initial Access': ['access', 'phishing', 'spearphishing', 'drive-by', 'exploit', 'external'],
            'Execution': ['execution', 'script', 'powershell', 'command', 'macro', 'wmi', 'xsl'],
            'Persistence': ['persistence', 'registry', 'startup', 'backdoor', 'service', 'scheduled'],
            'Privilege Escalation': ['escalation', 'privilege', 'sudo', 'kernel', 'bypass', 'injection'],
            'Defense Evasion': ['evasion', 'bypass', 'rootkit', 'obfuscation', 'masquerading'],
            'Credential Access': ['credential', 'password', 'hash', 'kerberos', 'ticket', 'keylogger'],
            'Discovery': ['discovery', 'network', 'system', 'account', 'domain', 'enumeration'],
            'Lateral Movement': ['lateral', 'movement', 'remote', 'service', 'psexec', 'rdp'],
            'Collection': ['collection', 'data', 'screenshot', 'keylogger', 'clipboard'],
            'Command and Control': ['command', 'control', 'c2', 'proxy', 'protocol', 'dns', 'web'],
            'Exfiltration': ['exfiltration', 'transfer', 'steganography', 'compression'],
            'Impact': ['impact', 'destruction', 'denial', 'service', 'dos', 'defacement', 'encryption']
        }
        
        # Extraire le nom et la description de la vulnérabilité
        vuln_name = vulnerability.get('name', '').lower()
        vuln_info = vulnerability.get('info', '').lower()
        
        # Combiner le nom et la description pour la recherche
        vuln_text = f"{vuln_name} {vuln_info}"
        
        # Identifier les tactiques potentielles
        potential_tactics = []
        for tactic, kw_list in keywords.items():
            for kw in kw_list:
                if kw in vuln_text:
                    potential_tactics.append(tactic)
                    break
        
        # Si aucune tactique n'est identifiée, utiliser des tactiques par défaut
        if not potential_tactics:
            potential_tactics = ['Initial Access', 'Execution']
        
        # Trouver les techniques correspondantes pour chaque tactique
        for tactic in set(potential_tactics):
            for technique_id, technique in self.techniques.items():
                # Vérifier si la technique appartient à la tactique
                if any(t.lower() == tactic.lower() for t in technique['tactics']):
                    # Calculer un score de correspondance simple
                    technique_name = technique['name'].lower()
                    technique_desc = technique['description'].lower()
                    
                    score = 0
                    for word in vuln_name.split():
                        if len(word) > 3:  # Ignorer les mots courts
                            if word in technique_name:
                                score += 3
                            if word in technique_desc:
                                score += 1
                    
                    if score > 0:
                        mapped_techniques.append({
                            'technique_id': technique_id,
                            'technique_name': technique['name'],
                            'tactic': tactic,
                            'score': score
                        })
        
        # Trier par score décroissant
        mapped_techniques.sort(key=lambda x: x['score'], reverse=True)
        
        # Limiter à 5 techniques maximum
        return mapped_techniques[:5]
    
    def map_attack_path_to_techniques(self, attack_path):
        """
        Mappe un chemin d'attaque complet aux techniques MITRE ATT&CK.
        
        Args:
            attack_path (list): Chemin d'attaque (liste de nœuds)
            
        Returns:
            dict: Mapping du chemin d'attaque aux techniques MITRE ATT&CK
        """
        path_mapping = {
            'techniques': [],
            'tactics': set(),
            'mitigations': []
        }
        
        # Parcourir chaque nœud du chemin
        for node in attack_path:
            node_type = node.get('type')
            
            if node_type == 'vulnerability':
                # Mapper la vulnérabilité aux techniques
                techniques = self.map_vulnerability_to_technique(node)
                
                for technique in techniques:
                    technique_id = technique['technique_id']
                    
                    # Ajouter la technique
                    if technique_id not in [t['technique_id'] for t in path_mapping['techniques']]:
                        path_mapping['techniques'].append({
                            'technique_id': technique_id,
                            'name': technique['technique_name'],
                            'tactic': technique['tactic']
                        })
                        
                        # Ajouter la tactique
                        path_mapping['tactics'].add(technique['tactic'])
                        
                        # Ajouter les mitigations associées
                        if technique_id in self.techniques:
                            for mitigation_id in self.techniques[technique_id].get('mitigations', []):
                                if mitigation_id in self.mitigations:
                                    mitigation = self.mitigations[mitigation_id]
                                    if mitigation_id not in [m['mitigation_id'] for m in path_mapping['mitigations']]:
                                        path_mapping['mitigations'].append({
                                            'mitigation_id': mitigation_id,
                                            'name': mitigation['name'],
                                            'description': mitigation['description']
                                        })
        
        # Convertir l'ensemble des tactiques en liste
        path_mapping['tactics'] = list(path_mapping['tactics'])
        
        return path_mapping
    
    def get_technique_details(self, technique_id):
        """
        Récupère les détails d'une technique MITRE ATT&CK.
        
        Args:
            technique_id (str): Identifiant de la technique (ex: T1566)
            
        Returns:
            dict: Détails de la technique
        """
        if technique_id in self.techniques:
            return self.techniques[technique_id]
        return None
    
    def get_mitigation_details(self, mitigation_id):
        """
        Récupère les détails d'une mitigation MITRE ATT&CK.
        
        Args:
            mitigation_id (str): Identifiant de la mitigation (ex: M1032)
            
        Returns:
            dict: Détails de la mitigation
        """
        if mitigation_id in self.mitigations:
            return self.mitigations[mitigation_id]
        return None
    
    def get_group_by_technique(self, technique_id):
        """
        Récupère les groupes d'attaquants utilisant une technique spécifique.
        
        Args:
            technique_id (str): Identifiant de la technique (ex: T1566)
            
        Returns:
            list: Liste des groupes utilisant cette technique
        """
        groups = []
        
        for group_id, group in self.groups.items():
            if technique_id in group.get('techniques', []):
                groups.append(group)
        
        return groups
    
    def get_software_by_technique(self, technique_id):
        """
        Récupère les logiciels malveillants utilisant une technique spécifique.
        
        Args:
            technique_id (str): Identifiant de la technique (ex: T1566)
            
        Returns:
            list: Liste des logiciels utilisant cette technique
        """
        software_list = []
        
        for software_id, software in self.software.items():
            if technique_id in software.get('techniques', []):
                software_list.append(software)
        
        return software_list
