#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse des chemins d'attaque critiques.
Ce module permet de détecter automatiquement les chemins d'attaque les plus critiques
dans un graphe d'attaque.
"""

import networkx as nx
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class AttackPathAnalyzer:
    """
    Classe pour l'analyse des chemins d'attaque critiques dans un graphe.
    """
    
    def __init__(self, graph):
        """
        Initialise l'analyseur avec un graphe d'attaque.
        
        Args:
            graph (nx.DiGraph): Graphe d'attaque NetworkX
        """
        self.graph = graph
        self.critical_paths = []
        self.node_scores = {}
        self.path_scores = {}
        
    def identify_entry_points(self):
        """
        Identifie les points d'entrée potentiels dans le réseau.
        
        Returns:
            list: Liste des nœuds identifiés comme points d'entrée
        """
        entry_points = []
        
        for node, attrs in self.graph.nodes(data=True):
            # Un point d'entrée est généralement un service exposé
            if attrs.get('type') == 'service':
                # Vérifier si le service est exposé sur Internet
                if any(self.graph.has_edge(src, node) for src in self.graph.predecessors(node) 
                       if self.graph.nodes[src].get('type') == 'host'):
                    entry_points.append(node)
            
            # Ou un utilisateur avec des privilèges externes
            elif attrs.get('type') == 'user' and attrs.get('external', False):
                entry_points.append(node)
        
        logger.info(f"Points d'entrée identifiés: {len(entry_points)}")
        return entry_points
    
    def identify_critical_assets(self):
        """
        Identifie les actifs critiques dans le réseau.
        
        Returns:
            list: Liste des nœuds identifiés comme actifs critiques
        """
        critical_assets = []
        
        for node, attrs in self.graph.nodes(data=True):
            # Un actif critique peut être un serveur de domaine
            if attrs.get('type') == 'host' and attrs.get('critical', False):
                critical_assets.append(node)
            
            # Ou un utilisateur administrateur
            elif attrs.get('type') == 'user' and attrs.get('admin', False):
                critical_assets.append(node)
            
            # Ou une base de données sensible
            elif attrs.get('type') == 'service' and 'database' in attrs.get('service', '').lower():
                critical_assets.append(node)
        
        logger.info(f"Actifs critiques identifiés: {len(critical_assets)}")
        return critical_assets
    
    def calculate_node_risk_scores(self):
        """
        Calcule les scores de risque pour chaque nœud du graphe.
        
        Returns:
            dict: Dictionnaire des scores de risque par nœud
        """
        scores = {}
        
        for node, attrs in self.graph.nodes(data=True):
            base_score = 1.0
            
            # Augmenter le score pour les vulnérabilités
            if attrs.get('type') == 'vulnerability':
                severity = attrs.get('severity', 0.0)
                base_score = 2.0 + (severity * 0.8)  # Score max: 10.0
            
            # Augmenter le score pour les services exposés
            elif attrs.get('type') == 'service':
                # Services critiques
                if attrs.get('service', '').lower() in ['ssh', 'rdp', 'smb', 'ftp', 'telnet']:
                    base_score = 3.0
                else:
                    base_score = 2.0
            
            # Augmenter le score pour les utilisateurs privilégiés
            elif attrs.get('type') == 'user':
                if attrs.get('admin', False):
                    base_score = 5.0
                elif attrs.get('privileged', False):
                    base_score = 3.0
                else:
                    base_score = 2.0
            
            # Augmenter le score pour les hôtes critiques
            elif attrs.get('type') == 'host':
                if attrs.get('critical', False):
                    base_score = 4.0
                else:
                    base_score = 2.0
            
            # Augmenter le score pour les exploits
            elif attrs.get('type') == 'exploit':
                rank = attrs.get('rank', 'normal').lower()
                if rank == 'excellent':
                    base_score = 5.0
                elif rank == 'great':
                    base_score = 4.0
                elif rank == 'good':
                    base_score = 3.0
                else:
                    base_score = 2.0
            
            scores[node] = base_score
        
        self.node_scores = scores
        return scores
    
    def find_all_attack_paths(self, entry_points=None, critical_assets=None):
        """
        Trouve tous les chemins d'attaque possibles entre les points d'entrée et les actifs critiques.
        
        Args:
            entry_points (list, optional): Liste des points d'entrée. Si None, ils seront détectés automatiquement.
            critical_assets (list, optional): Liste des actifs critiques. Si None, ils seront détectés automatiquement.
            
        Returns:
            list: Liste des chemins d'attaque (chaque chemin est une liste de nœuds)
        """
        if entry_points is None:
            entry_points = self.identify_entry_points()
        
        if critical_assets is None:
            critical_assets = self.identify_critical_assets()
        
        if not entry_points or not critical_assets:
            logger.warning("Aucun point d'entrée ou actif critique trouvé.")
            return []
        
        all_paths = []
        
        for source in entry_points:
            for target in critical_assets:
                try:
                    # Trouver tous les chemins simples entre source et cible
                    paths = list(nx.all_simple_paths(self.graph, source, target, cutoff=10))
                    all_paths.extend(paths)
                except nx.NetworkXNoPath:
                    continue
        
        logger.info(f"Chemins d'attaque trouvés: {len(all_paths)}")
        return all_paths
    
    def calculate_path_risk_scores(self, paths=None):
        """
        Calcule les scores de risque pour chaque chemin d'attaque.
        
        Args:
            paths (list, optional): Liste des chemins d'attaque. Si None, tous les chemins seront calculés.
            
        Returns:
            dict: Dictionnaire des scores de risque par chemin
        """
        if not self.node_scores:
            self.calculate_node_risk_scores()
        
        if paths is None:
            paths = self.find_all_attack_paths()
        
        path_scores = {}
        
        for i, path in enumerate(paths):
            # Calculer le score du chemin basé sur les scores des nœuds
            node_scores = [self.node_scores.get(node, 1.0) for node in path]
            
            # Le score du chemin est la somme des scores des nœuds, pondérée par la longueur
            path_score = sum(node_scores) * (1.0 / (1 + 0.1 * len(path)))
            
            path_scores[i] = {
                'path': path,
                'score': path_score,
                'length': len(path)
            }
        
        # Trier les chemins par score décroissant
        sorted_paths = sorted(path_scores.items(), key=lambda x: x[1]['score'], reverse=True)
        
        # Reconstruire le dictionnaire trié
        self.path_scores = {i: data for i, (_, data) in enumerate(sorted_paths)}
        
        return self.path_scores
    
    def get_critical_attack_paths(self, top_n=5):
        """
        Retourne les chemins d'attaque les plus critiques.
        
        Args:
            top_n (int, optional): Nombre de chemins critiques à retourner. Par défaut 5.
            
        Returns:
            list: Liste des chemins d'attaque critiques avec leurs scores
        """
        if not self.path_scores:
            self.calculate_path_risk_scores()
        
        # Prendre les top_n chemins
        critical_paths = []
        for i in range(min(top_n, len(self.path_scores))):
            critical_paths.append(self.path_scores[i])
        
        self.critical_paths = critical_paths
        return critical_paths
    
    def get_path_details(self, path):
        """
        Retourne les détails d'un chemin d'attaque spécifique.
        
        Args:
            path (list): Chemin d'attaque (liste de nœuds)
            
        Returns:
            dict: Détails du chemin d'attaque
        """
        details = {
            'nodes': [],
            'edges': []
        }
        
        # Détails des nœuds
        for node in path:
            node_data = self.graph.nodes[node].copy()
            node_data['id'] = node
            node_data['risk_score'] = self.node_scores.get(node, 1.0)
            details['nodes'].append(node_data)
        
        # Détails des arêtes
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            if self.graph.has_edge(source, target):
                edge_data = self.graph.edges[source, target].copy()
                edge_data['source'] = source
                edge_data['target'] = target
                details['edges'].append(edge_data)
        
        return details
    
    def get_attack_path_summary(self):
        """
        Génère un résumé des chemins d'attaque critiques.
        
        Returns:
            dict: Résumé des chemins d'attaque critiques
        """
        if not self.critical_paths:
            self.get_critical_attack_paths()
        
        summary = {
            'total_paths': len(self.path_scores),
            'critical_paths': len(self.critical_paths),
            'entry_points': self.identify_entry_points(),
            'critical_assets': self.identify_critical_assets(),
            'paths': []
        }
        
        for path_data in self.critical_paths:
            path = path_data['path']
            
            path_summary = {
                'path': path,
                'score': path_data['score'],
                'length': path_data['length'],
                'details': self.get_path_details(path)
            }
            
            summary['paths'].append(path_summary)
        
        return summary
