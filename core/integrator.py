#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'intégration des modules pour AttackPathGraph.
Ce module permet d'intégrer tous les modules développés dans le projet.
"""

import os
import logging
import networkx as nx
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AttackPathGraphIntegrator:
    """
    Classe pour l'intégration des modules AttackPathGraph.
    """
    
    def __init__(self):
        """
        Initialise l'intégrateur.
        """
        self.graph = nx.DiGraph()
        self.parsers = {}
        self.analyzer = None
        self.scorer = None
        self.mitre_integration = None
        self.report_generator = None
        self.web_interface = None
        
        # Charger les modules
        self._load_modules()
    
    def _load_modules(self):
        """
        Charge tous les modules disponibles.
        """
        try:
            # Parsers
            from core.parsers import load_nmap_data, load_bloodhound_data
            self.parsers['nmap'] = load_nmap_data
            self.parsers['bloodhound'] = load_bloodhound_data
            
            # Nouveaux parsers
            try:
                from core.parsers.openvas_parser import load_openvas_data
                self.parsers['openvas'] = load_openvas_data
                logger.info("Module OpenVAS chargé avec succès")
            except ImportError:
                logger.warning("Module OpenVAS non disponible")
            
            try:
                from core.parsers.metasploit_parser import load_metasploit_data
                self.parsers['metasploit'] = load_metasploit_data
                logger.info("Module Metasploit chargé avec succès")
            except ImportError:
                logger.warning("Module Metasploit non disponible")
            
            # Analyseur de chemins d'attaque
            try:
                from core.analysis.path_analyzer import AttackPathAnalyzer
                self.analyzer_class = AttackPathAnalyzer
                logger.info("Module d'analyse des chemins d'attaque chargé avec succès")
            except ImportError:
                logger.warning("Module d'analyse des chemins d'attaque non disponible")
            
            # Scoring de risque
            try:
                from core.scoring.risk_scorer import RiskScorer
                self.scorer_class = RiskScorer
                logger.info("Module de scoring de risque chargé avec succès")
            except ImportError:
                logger.warning("Module de scoring de risque non disponible")
            
            # Intégration MITRE ATT&CK
            try:
                from core.analysis.mitre_attack import MitreAttackIntegration
                self.mitre_class = MitreAttackIntegration
                logger.info("Module d'intégration MITRE ATT&CK chargé avec succès")
            except ImportError:
                logger.warning("Module d'intégration MITRE ATT&CK non disponible")
            
            # Générateur de rapports
            try:
                from core.reporting.report_generator import ReportGenerator
                self.report_class = ReportGenerator
                logger.info("Module de génération de rapports chargé avec succès")
            except ImportError:
                logger.warning("Module de génération de rapports non disponible")
            
            # Interface web
            try:
                from core.web.web_interface import WebInterface
                self.web_class = WebInterface
                logger.info("Module d'interface web chargé avec succès")
            except ImportError:
                logger.warning("Module d'interface web non disponible")
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des modules: {e}")
    
    def load_data(self, data_type, file_path):
        """
        Charge des données depuis un fichier.
        
        Args:
            data_type (str): Type de données ('nmap', 'bloodhound', 'openvas', 'metasploit')
            file_path (str): Chemin vers le fichier
            
        Returns:
            dict: Données chargées
        """
        if data_type not in self.parsers:
            raise ValueError(f"Type de données non supporté: {data_type}")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Fichier non trouvé: {file_path}")
        
        logger.info(f"Chargement des données {data_type} depuis {file_path}")
        return self.parsers[data_type](file_path)
    
    def add_data_to_graph(self, data, data_type):
        """
        Ajoute des données au graphe.
        
        Args:
            data (dict): Données à ajouter
            data_type (str): Type de données ('nmap', 'bloodhound', 'openvas', 'metasploit')
        """
        if data_type == 'nmap':
            self._add_nmap_data(data)
        elif data_type == 'bloodhound':
            self._add_bloodhound_data(data)
        elif data_type == 'openvas':
            self._add_openvas_data(data)
        elif data_type == 'metasploit':
            self._add_metasploit_data(data)
        else:
            raise ValueError(f"Type de données non supporté: {data_type}")
    
    def _add_nmap_data(self, data):
        """
        Ajoute des données Nmap au graphe.
        
        Args:
            data (dict): Données Nmap
        """
        for host, services in data.items():
            self.graph.add_node(host, type="host")
            for port, service in services:
                self.graph.add_node(f"{host}:{port}", type="service", service=service, port=port)
                self.graph.add_edge(host, f"{host}:{port}", label="exposes")
    
    def _add_bloodhound_data(self, data):
        """
        Ajoute des données BloodHound au graphe.
        
        Args:
            data (dict): Données BloodHound
        """
        if "relationships" in data:
            for node_id, attrs in data.get("nodes", {}).items():
                self.graph.add_node(node_id, **attrs)

            for relation in data.get("relationships", []):
                source = relation.get("source")
                target = relation.get("target")
                label = relation.get("label", "can_access")
                if source and target:
                    self.graph.add_edge(source, target, label=label)
            return

        for user, targets in data.items():
            self.graph.add_node(user, type="user")
            for tgt in targets:
                self.graph.add_edge(user, tgt, label="can_access")
    
    def _add_openvas_data(self, data):
        """
        Ajoute des données OpenVAS au graphe.
        
        Args:
            data (dict): Données OpenVAS
        """
        # Ajouter les hôtes
        for host_id, host_data in data.get('hosts', {}).items():
            if not self.graph.has_node(host_id):
                self.graph.add_node(host_id, **host_data)
        
        # Ajouter les vulnérabilités
        for vuln_id, vuln_data in data.get('vulnerabilities', {}).items():
            self.graph.add_node(vuln_id, **vuln_data)
        
        # Ajouter les relations
        for relation in data.get('relations', []):
            source = relation.get('source')
            target = relation.get('target')
            label = relation.get('label', 'related_to')
            
            if source and target:
                self.graph.add_edge(source, target, label=label)
    
    def _add_metasploit_data(self, data):
        """
        Ajoute des données Metasploit au graphe.
        
        Args:
            data (dict): Données Metasploit
        """
        # Ajouter les hôtes
        for host_id, host_data in data.get('hosts', {}).items():
            if not self.graph.has_node(host_id):
                self.graph.add_node(host_id, **host_data)
        
        # Ajouter les vulnérabilités
        for vuln_id, vuln_data in data.get('vulnerabilities', {}).items():
            self.graph.add_node(vuln_id, **vuln_data)
        
        # Ajouter les exploits
        for exploit_id, exploit_data in data.get('exploits', {}).items():
            self.graph.add_node(exploit_id, **exploit_data)
        
        # Ajouter les relations
        for relation in data.get('relations', []):
            source = relation.get('source')
            target = relation.get('target')
            label = relation.get('label', 'related_to')
            
            if source and target:
                self.graph.add_edge(source, target, label=label)
    
    def initialize_analyzer(self):
        """
        Initialise l'analyseur de chemins d'attaque.
        
        Returns:
            AttackPathAnalyzer: Analyseur de chemins d'attaque
        """
        if not hasattr(self, 'analyzer_class'):
            raise ImportError("Module d'analyse des chemins d'attaque non disponible")
        
        self.analyzer = self.analyzer_class(self.graph)
        return self.analyzer
    
    def initialize_scorer(self):
        """
        Initialise le calculateur de scores de risque.
        
        Returns:
            RiskScorer: Calculateur de scores de risque
        """
        if not hasattr(self, 'scorer_class'):
            raise ImportError("Module de scoring de risque non disponible")
        
        self.scorer = self.scorer_class(self.graph)
        return self.scorer
    
    def initialize_mitre_integration(self):
        """
        Initialise l'intégration MITRE ATT&CK.
        
        Returns:
            MitreAttackIntegration: Intégration MITRE ATT&CK
        """
        if not hasattr(self, 'mitre_class'):
            raise ImportError("Module d'intégration MITRE ATT&CK non disponible")
        
        self.mitre_integration = self.mitre_class()
        return self.mitre_integration
    
    def initialize_report_generator(self):
        """
        Initialise le générateur de rapports.
        
        Returns:
            ReportGenerator: Générateur de rapports
        """
        if not hasattr(self, 'report_class'):
            raise ImportError("Module de génération de rapports non disponible")
        
        self.report_generator = self.report_class(self.graph, self.analyzer)
        return self.report_generator
    
    def initialize_web_interface(self):
        """
        Initialise l'interface web.
        
        Returns:
            WebInterface: Interface web
        """
        if not hasattr(self, 'web_class'):
            raise ImportError("Module d'interface web non disponible")
        
        self.web_interface = self.web_class(
            self.graph, 
            self.analyzer, 
            self.scorer, 
            self.mitre_integration
        )
        return self.web_interface
    
    def analyze_attack_paths(self):
        """
        Analyse les chemins d'attaque.
        
        Returns:
            dict: Résumé des chemins d'attaque
        """
        if self.analyzer is None:
            self.initialize_analyzer()
        
        # Identifier les points d'entrée et les actifs critiques
        entry_points = self.analyzer.identify_entry_points()
        critical_assets = self.analyzer.identify_critical_assets()
        
        # Trouver tous les chemins d'attaque
        paths = self.analyzer.find_all_attack_paths(entry_points, critical_assets)
        
        # Calculer les scores de risque
        if self.scorer is None:
            self.initialize_scorer()
        
        path_scores = self.scorer.calculate_all_path_scores(paths)
        
        # Obtenir les chemins critiques
        critical_paths = self.analyzer.get_critical_attack_paths()
        
        return self.analyzer.get_attack_path_summary()
    
    def generate_report(self, output_path, format='html'):
        """
        Génère un rapport.
        
        Args:
            output_path (str): Chemin de sortie pour le rapport
            format (str, optional): Format du rapport ('html' ou 'pdf'). Par défaut 'html'.
            
        Returns:
            str: Chemin du rapport généré
        """
        if self.report_generator is None:
            self.initialize_report_generator()
        
        if format.lower() == 'html':
            return self.report_generator.generate_html_report(output_path)
        elif format.lower() == 'pdf':
            return self.report_generator.generate_pdf_report(output_path)
        else:
            raise ValueError(f"Format de rapport non supporté: {format}")
    
    def start_web_interface(self, host='0.0.0.0', port=5000, debug=False, open_browser=True):
        """
        Démarre l'interface web.
        
        Args:
            host (str, optional): Hôte d'écoute. Par défaut '0.0.0.0'.
            port (int, optional): Port d'écoute. Par défaut 5000.
            debug (bool, optional): Mode debug. Par défaut False.
            open_browser (bool, optional): Ouvrir le navigateur. Par défaut True.
        """
        if self.web_interface is None:
            self.initialize_web_interface()
        
        self.web_interface.start(host, port, debug, open_browser)
    
    def export_to_neo4j(self, uri=None, user=None, password=None):
        """
        Exporte le graphe vers Neo4j.
        
        Args:
            uri (str, optional): URI de connexion Neo4j. Si None, utilise la variable d'environnement NEO4J_URI ou la valeur par défaut.
            user (str, optional): Nom d'utilisateur Neo4j. Si None, utilise la variable d'environnement NEO4J_USER ou la valeur par défaut.
            password (str, optional): Mot de passe Neo4j. Si None, utilise la variable d'environnement NEO4J_PASSWORD ou la valeur par défaut.
        """
        import os
        from py2neo import Graph, Node, Relationship
        
        # Utiliser les variables d'environnement ou les valeurs par défaut
        uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = user or os.environ.get("NEO4J_USER", "neo4j")
        password = password or os.environ.get("NEO4J_PASSWORD", "neo4j")
        
        logger.info(f"Export vers Neo4j: {uri}")
        neo = Graph(uri, auth=(user, password))
        neo.delete_all()
        
        # Exporter les nœuds
        for node, attrs in self.graph.nodes(data=True):
            neo_node = Node(attrs.get("type", "Node"), name=node)
            
            # Ajouter les attributs
            for key, value in attrs.items():
                if key != "type":
                    neo_node[key] = value
            
            neo.merge(neo_node)
        
        # Exporter les arêtes
        for src, dst, attrs in self.graph.edges(data=True):
            a = Node(self.graph.nodes[src].get("type", "Node"), name=src)
            b = Node(self.graph.nodes[dst].get("type", "Node"), name=dst)
            rel = Relationship(a, attrs.get("label", "LINKS_TO"), b)
            
            # Ajouter les attributs
            for key, value in attrs.items():
                if key != "label":
                    rel[key] = value
            
            neo.merge(rel)
        
        logger.info("Export terminé")
