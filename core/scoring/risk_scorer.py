#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de calcul des scores de risque pour AttackPathGraph.
Ce module permet d'évaluer la criticité des chemins d'attaque.
"""

import logging
import math
from collections import defaultdict

logger = logging.getLogger(__name__)

class RiskScorer:
    """
    Classe pour le calcul des scores de risque sur les chemins d'attaque.
    """
    
    def __init__(self, graph):
        """
        Initialise le calculateur de scores de risque.
        
        Args:
            graph (nx.DiGraph): Graphe d'attaque NetworkX
        """
        self.graph = graph
        self.node_scores = {}
        self.path_scores = {}
        self.cvss_weights = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},  # Attack Vector
            'AC': {'L': 0.77, 'H': 0.44},                      # Attack Complexity
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},           # Privileges Required
            'UI': {'N': 0.85, 'R': 0.62},                      # User Interaction
            'S': {'U': 6.42, 'C': 7.52},                       # Scope
            'C': {'N': 0, 'L': 0.22, 'H': 0.56},               # Confidentiality
            'I': {'N': 0, 'L': 0.22, 'H': 0.56},               # Integrity
            'A': {'N': 0, 'L': 0.22, 'H': 0.56}                # Availability
        }
    
    def calculate_base_node_scores(self):
        """
        Calcule les scores de base pour chaque nœud du graphe.
        
        Returns:
            dict: Dictionnaire des scores de base par nœud
        """
        scores = {}
        
        for node, attrs in self.graph.nodes(data=True):
            base_score = 1.0
            
            # Scores pour les vulnérabilités
            if attrs.get('type') == 'vulnerability':
                # Si CVSS est disponible, l'utiliser
                if 'cvss' in attrs:
                    base_score = self._calculate_cvss_score(attrs['cvss'])
                # Sinon, utiliser la sévérité
                elif 'severity' in attrs:
                    severity = float(attrs['severity'])
                    base_score = min(10.0, severity * 2.0)  # Échelle 0-10
                else:
                    base_score = 5.0  # Score par défaut
            
            # Scores pour les services
            elif attrs.get('type') == 'service':
                service = attrs.get('service', '').lower()
                # Services critiques
                if service in ['ssh', 'rdp', 'smb', 'ftp', 'telnet', 'vnc']:
                    base_score = 7.0
                # Services web
                elif service in ['http', 'https', 'www']:
                    base_score = 6.0
                # Services de base de données
                elif any(db in service for db in ['sql', 'oracle', 'mysql', 'postgres', 'db']):
                    base_score = 8.0
                # Autres services
                else:
                    base_score = 4.0
            
            # Scores pour les utilisateurs
            elif attrs.get('type') == 'user':
                if attrs.get('admin', False):
                    base_score = 9.0  # Administrateur
                elif attrs.get('privileged', False):
                    base_score = 7.0  # Utilisateur privilégié
                elif attrs.get('service_account', False):
                    base_score = 6.0  # Compte de service
                else:
                    base_score = 3.0  # Utilisateur standard
            
            # Scores pour les hôtes
            elif attrs.get('type') == 'host':
                if attrs.get('critical', False):
                    base_score = 8.0  # Serveur critique
                elif 'server' in attrs.get('hostname', '').lower():
                    base_score = 6.0  # Serveur
                else:
                    base_score = 4.0  # Poste de travail
            
            # Scores pour les exploits
            elif attrs.get('type') == 'exploit':
                rank = attrs.get('rank', 'normal').lower()
                if rank == 'excellent':
                    base_score = 9.0
                elif rank == 'great':
                    base_score = 7.5
                elif rank == 'good':
                    base_score = 6.0
                elif rank == 'normal':
                    base_score = 4.5
                elif rank == 'average':
                    base_score = 3.0
                else:
                    base_score = 2.0
            
            scores[node] = base_score
        
        self.node_scores = scores
        return scores
    
    def _calculate_cvss_score(self, cvss_vector):
        """
        Calcule un score CVSS à partir d'un vecteur CVSS.
        
        Args:
            cvss_vector (str): Vecteur CVSS (ex: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            
        Returns:
            float: Score CVSS calculé
        """
        # Si c'est déjà un score numérique
        if isinstance(cvss_vector, (int, float)):
            return float(cvss_vector)
        
        # Si c'est un vecteur CVSS
        if not isinstance(cvss_vector, str):
            return 5.0  # Valeur par défaut
        
        try:
            # Extraire les composants du vecteur
            components = {}
            if '/' in cvss_vector:
                parts = cvss_vector.split('/')
                for part in parts:
                    if ':' in part:
                        key, value = part.split(':')
                        components[key] = value
            
            # Calculer le score de base
            impact = 0
            exploitability = 0
            
            # Impact
            if 'S' in components and 'C' in components and 'I' in components and 'A' in components:
                scope = components['S']
                conf = components['C']
                integ = components['I']
                avail = components['A']
                
                impact_sub = self.cvss_weights['C'].get(conf, 0) + self.cvss_weights['I'].get(integ, 0) + self.cvss_weights['A'].get(avail, 0)
                
                if scope == 'U':
                    impact = 6.42 * impact_sub
                else:
                    impact = 7.52 * (impact_sub - 0.029) - 3.25 * pow(impact_sub - 0.02, 15)
            
            # Exploitability
            if 'AV' in components and 'AC' in components and 'PR' in components and 'UI' in components:
                attack_vector = components['AV']
                attack_complexity = components['AC']
                privileges_required = components['PR']
                user_interaction = components['UI']
                
                exploitability = 8.22 * self.cvss_weights['AV'].get(attack_vector, 0.2) * self.cvss_weights['AC'].get(attack_complexity, 0.44) * self.cvss_weights['PR'].get(privileges_required, 0.27) * self.cvss_weights['UI'].get(user_interaction, 0.62)
            
            # Score final
            if impact <= 0:
                return 0
            
            if 'S' in components and components['S'] == 'U':
                return min(10, round(((impact + exploitability) * 10) / 15, 1))
            else:
                return min(10, round(1.08 * ((impact + exploitability) * 10) / 15, 1))
                
        except Exception as e:
            logger.warning(f"Erreur lors du calcul du score CVSS: {e}")
            return 5.0  # Valeur par défaut
    
    def calculate_path_risk_score(self, path):
        """
        Calcule le score de risque pour un chemin d'attaque spécifique.
        
        Args:
            path (list): Liste des nœuds formant le chemin d'attaque
            
        Returns:
            float: Score de risque du chemin
        """
        if not self.node_scores:
            self.calculate_base_node_scores()
        
        if not path:
            return 0.0
        
        # Récupérer les scores des nœuds
        node_scores = [self.node_scores.get(node, 1.0) for node in path]
        
        # Facteurs de pondération
        path_length = len(path)
        length_factor = 1.0 / (1 + 0.1 * path_length)  # Pénalité pour les chemins longs
        
        # Calculer le score moyen des nœuds
        avg_node_score = sum(node_scores) / path_length if path_length > 0 else 0
        
        # Calculer le score maximum des nœuds
        max_node_score = max(node_scores) if node_scores else 0
        
        # Calculer le score de risque du chemin
        # Formule: (0.7 * score_moyen + 0.3 * score_max) * facteur_longueur
        path_score = (0.7 * avg_node_score + 0.3 * max_node_score) * length_factor
        
        return min(10.0, path_score)
    
    def calculate_all_path_scores(self, paths):
        """
        Calcule les scores de risque pour tous les chemins d'attaque.
        
        Args:
            paths (list): Liste des chemins d'attaque
            
        Returns:
            dict: Dictionnaire des scores par chemin
        """
        if not self.node_scores:
            self.calculate_base_node_scores()
        
        path_scores = {}
        
        for i, path in enumerate(paths):
            score = self.calculate_path_risk_score(path)
            path_scores[i] = {
                'path': path,
                'score': score,
                'length': len(path),
                'risk_level': self._get_risk_level(score)
            }
        
        # Trier les chemins par score décroissant
        sorted_paths = sorted(path_scores.items(), key=lambda x: x[1]['score'], reverse=True)
        
        # Reconstruire le dictionnaire trié
        self.path_scores = {i: data for i, (_, data) in enumerate(sorted_paths)}
        
        return self.path_scores
    
    def _get_risk_level(self, score):
        """
        Détermine le niveau de risque en fonction du score.
        
        Args:
            score (float): Score de risque
            
        Returns:
            str: Niveau de risque (Critical, High, Medium, Low, Info)
        """
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 2.0:
            return "Low"
        else:
            return "Info"
    
    def get_risk_summary(self):
        """
        Génère un résumé des risques identifiés.
        
        Returns:
            dict: Résumé des risques
        """
        if not self.path_scores:
            return {
                'total_paths': 0,
                'risk_levels': {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'Info': 0
                },
                'highest_risk_score': 0.0,
                'average_risk_score': 0.0
            }
        
        # Compter les chemins par niveau de risque
        risk_levels = defaultdict(int)
        for path_data in self.path_scores.values():
            risk_level = path_data['risk_level']
            risk_levels[risk_level] += 1
        
        # Calculer le score moyen
        avg_score = sum(path_data['score'] for path_data in self.path_scores.values()) / len(self.path_scores)
        
        # Trouver le score maximum
        max_score = max(path_data['score'] for path_data in self.path_scores.values())
        
        return {
            'total_paths': len(self.path_scores),
            'risk_levels': dict(risk_levels),
            'highest_risk_score': max_score,
            'average_risk_score': avg_score
        }
    
    def get_node_risk_contribution(self):
        """
        Calcule la contribution de chaque nœud au risque global.
        
        Returns:
            dict: Contribution de chaque nœud au risque
        """
        if not self.path_scores:
            return {}
        
        node_contributions = defaultdict(float)
        node_occurrences = defaultdict(int)
        
        # Compter les occurrences de chaque nœud dans les chemins
        for path_data in self.path_scores.values():
            path = path_data['path']
            path_score = path_data['score']
            
            for node in path:
                node_contributions[node] += path_score
                node_occurrences[node] += 1
        
        # Calculer la contribution moyenne
        node_risk = {}
        for node, contribution in node_contributions.items():
            occurrences = node_occurrences[node]
            avg_contribution = contribution / occurrences if occurrences > 0 else 0
            
            node_risk[node] = {
                'contribution': contribution,
                'occurrences': occurrences,
                'avg_contribution': avg_contribution,
                'base_score': self.node_scores.get(node, 0.0),
                'type': self.graph.nodes[node].get('type', 'unknown')
            }
        
        # Trier par contribution décroissante
        sorted_nodes = sorted(node_risk.items(), key=lambda x: x[1]['contribution'], reverse=True)
        
        return {node: data for node, data in sorted_nodes}
