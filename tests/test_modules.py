#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de test pour valider le fonctionnement des modules AttackPathGraph.
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ajouter le répertoire parent au chemin de recherche
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_parsers_check():
    """
    Teste les modules de parsing.
    """
    logger.info("Test des modules de parsing...")
    
    # Importer les modules
    try:
        from core.parsers.parsers import load_nmap_data, load_bloodhound_data
        from core.parsers.openvas_parser import load_openvas_data
        from core.parsers.metasploit_parser import load_metasploit_data
        
        logger.info("✅ Modules de parsing importés avec succès")
    except ImportError as e:
        logger.error(f"❌ Erreur lors de l'import des modules de parsing: {e}")
        return False
    
    # Tester avec des fichiers d'exemple
    demo_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'demo')
    
    # Tester Nmap
    try:
        nmap_file = os.path.join(demo_dir, 'nmap_sample.xml')
        if os.path.exists(nmap_file):
            nmap_data = load_nmap_data(nmap_file)
            logger.info(f"✅ Parsing Nmap réussi: {len(nmap_data)} hôtes trouvés")
        else:
            logger.warning(f"⚠️ Fichier d'exemple Nmap non trouvé: {nmap_file}")
    except Exception as e:
        logger.error(f"❌ Erreur lors du parsing Nmap: {e}")
        return False
    
    # Tester BloodHound
    try:
        bh_file = os.path.join(demo_dir, 'bloodhound_sample.json')
        if os.path.exists(bh_file):
            bh_data = load_bloodhound_data(bh_file)
            logger.info(f"✅ Parsing BloodHound réussi: {len(bh_data)} relations trouvées")
        else:
            logger.warning(f"⚠️ Fichier d'exemple BloodHound non trouvé: {bh_file}")
    except Exception as e:
        logger.error(f"❌ Erreur lors du parsing BloodHound: {e}")
        return False
    
    # Créer des exemples pour OpenVAS et Metasploit si nécessaire
    if not os.path.exists(os.path.join(demo_dir, 'openvas_sample.xml')):
        create_openvas_sample(os.path.join(demo_dir, 'openvas_sample.xml'))
    
    if not os.path.exists(os.path.join(demo_dir, 'metasploit_sample.json')):
        create_metasploit_sample(os.path.join(demo_dir, 'metasploit_sample.json'))
    
    # Tester OpenVAS
    try:
        openvas_file = os.path.join(demo_dir, 'openvas_sample.xml')
        if os.path.exists(openvas_file):
            openvas_data = load_openvas_data(openvas_file)
            logger.info(f"✅ Parsing OpenVAS réussi: {len(openvas_data['hosts'])} hôtes, {len(openvas_data['vulnerabilities'])} vulnérabilités")
        else:
            logger.warning(f"⚠️ Fichier d'exemple OpenVAS non trouvé: {openvas_file}")
    except Exception as e:
        logger.error(f"❌ Erreur lors du parsing OpenVAS: {e}")
        return False
    
    # Tester Metasploit
    try:
        metasploit_file = os.path.join(demo_dir, 'metasploit_sample.json')
        if os.path.exists(metasploit_file):
            metasploit_data = load_metasploit_data(metasploit_file)
            logger.info(f"✅ Parsing Metasploit réussi: {len(metasploit_data['hosts'])} hôtes, {len(metasploit_data['vulnerabilities'])} vulnérabilités")
        else:
            logger.warning(f"⚠️ Fichier d'exemple Metasploit non trouvé: {metasploit_file}")
    except Exception as e:
        logger.error(f"❌ Erreur lors du parsing Metasploit: {e}")
        return False
    
    logger.info("✅ Test des modules de parsing terminé avec succès")
    return True

def run_analysis_check():
    """
    Teste les modules d'analyse.
    """
    logger.info("Test des modules d'analyse...")
    
    # Importer les modules
    try:
        from core.analysis.path_analyzer import AttackPathAnalyzer
        from core.analysis.mitre_attack import MitreAttackIntegration
        import networkx as nx
        
        logger.info("✅ Modules d'analyse importés avec succès")
    except ImportError as e:
        logger.error(f"❌ Erreur lors de l'import des modules d'analyse: {e}")
        return False
    
    # Créer un graphe de test
    try:
        G = nx.DiGraph()
        
        # Ajouter des nœuds
        G.add_node("192.168.1.1", type="host", os="Windows")
        G.add_node("192.168.1.1:80", type="service", service="http")
        G.add_node("192.168.1.1:22", type="service", service="ssh")
        G.add_node("192.168.1.2", type="host", os="Linux")
        G.add_node("192.168.1.2:22", type="service", service="ssh")
        G.add_node("admin", type="user", admin=True)
        G.add_node("user", type="user", admin=False)
        G.add_node("vuln1", type="vulnerability", name="SQL Injection", severity=8.5)
        G.add_node("vuln2", type="vulnerability", name="XSS", severity=6.5)
        
        # Ajouter des arêtes
        G.add_edge("192.168.1.1", "192.168.1.1:80", label="exposes")
        G.add_edge("192.168.1.1", "192.168.1.1:22", label="exposes")
        G.add_edge("192.168.1.2", "192.168.1.2:22", label="exposes")
        G.add_edge("192.168.1.1:80", "vuln1", label="has_vulnerability")
        G.add_edge("192.168.1.1:80", "vuln2", label="has_vulnerability")
        G.add_edge("user", "192.168.1.1", label="can_access")
        G.add_edge("admin", "192.168.1.2", label="can_access")
        
        logger.info("✅ Graphe de test créé avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la création du graphe de test: {e}")
        return False
    
    # Tester l'analyseur de chemins d'attaque
    try:
        analyzer = AttackPathAnalyzer(G)
        
        # Identifier les points d'entrée et les actifs critiques
        entry_points = analyzer.identify_entry_points()
        critical_assets = analyzer.identify_critical_assets()
        
        logger.info(f"✅ Points d'entrée identifiés: {len(entry_points)}")
        logger.info(f"✅ Actifs critiques identifiés: {len(critical_assets)}")
        
        # Trouver les chemins d'attaque
        paths = analyzer.find_all_attack_paths(entry_points, critical_assets)
        logger.info(f"✅ Chemins d'attaque trouvés: {len(paths)}")
        
        # Calculer les scores des nœuds
        node_scores = analyzer.calculate_node_risk_scores()
        logger.info(f"✅ Scores des nœuds calculés: {len(node_scores)}")
        
        # Obtenir les chemins critiques
        critical_paths = analyzer.get_critical_attack_paths()
        logger.info(f"✅ Chemins critiques identifiés: {len(critical_paths)}")
        
        # Obtenir le résumé
        summary = analyzer.get_attack_path_summary()
        logger.info(f"✅ Résumé généré avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'analyse des chemins d'attaque: {e}")
        return False
    
    # Tester l'intégration MITRE ATT&CK
    try:
        mitre = MitreAttackIntegration()
        
        # Mapper une vulnérabilité à une technique
        vuln = {"name": "SQL Injection", "info": "Possible SQL injection in login form"}
        techniques = mitre.map_vulnerability_to_technique(vuln)
        
        if techniques:
            logger.info(f"✅ Vulnérabilité mappée à {len(techniques)} techniques MITRE ATT&CK")
        else:
            logger.warning("⚠️ Aucune technique MITRE ATT&CK trouvée pour la vulnérabilité")
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'intégration MITRE ATT&CK: {e}")
        return False
    
    logger.info("✅ Test des modules d'analyse terminé avec succès")
    return True

def run_scoring_check():
    """
    Teste les modules de scoring.
    """
    logger.info("Test des modules de scoring...")
    
    # Importer les modules
    try:
        from core.scoring.risk_scorer import RiskScorer
        import networkx as nx
        
        logger.info("✅ Modules de scoring importés avec succès")
    except ImportError as e:
        logger.error(f"❌ Erreur lors de l'import des modules de scoring: {e}")
        return False
    
    # Créer un graphe de test
    try:
        G = nx.DiGraph()
        
        # Ajouter des nœuds
        G.add_node("192.168.1.1", type="host", os="Windows")
        G.add_node("192.168.1.1:80", type="service", service="http")
        G.add_node("192.168.1.1:22", type="service", service="ssh")
        G.add_node("192.168.1.2", type="host", os="Linux")
        G.add_node("192.168.1.2:22", type="service", service="ssh")
        G.add_node("admin", type="user", admin=True)
        G.add_node("user", type="user", admin=False)
        G.add_node("vuln1", type="vulnerability", name="SQL Injection", severity=8.5)
        G.add_node("vuln2", type="vulnerability", name="XSS", severity=6.5)
        
        # Ajouter des arêtes
        G.add_edge("192.168.1.1", "192.168.1.1:80", label="exposes")
        G.add_edge("192.168.1.1", "192.168.1.1:22", label="exposes")
        G.add_edge("192.168.1.2", "192.168.1.2:22", label="exposes")
        G.add_edge("192.168.1.1:80", "vuln1", label="has_vulnerability")
        G.add_edge("192.168.1.1:80", "vuln2", label="has_vulnerability")
        G.add_edge("user", "192.168.1.1", label="can_access")
        G.add_edge("admin", "192.168.1.2", label="can_access")
        
        logger.info("✅ Graphe de test créé avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la création du graphe de test: {e}")
        return False
    
    # Tester le scoring de risque
    try:
        scorer = RiskScorer(G)
        
        # Calculer les scores de base des nœuds
        node_scores = scorer.calculate_base_node_scores()
        logger.info(f"✅ Scores de base des nœuds calculés: {len(node_scores)}")
        
        # Calculer le score d'un chemin
        path = ["user", "192.168.1.1", "192.168.1.1:80", "vuln1"]
        path_score = scorer.calculate_path_risk_score(path)
        logger.info(f"✅ Score du chemin calculé: {path_score}")
        
        # Calculer les scores de tous les chemins
        paths = [
            ["user", "192.168.1.1", "192.168.1.1:80", "vuln1"],
            ["user", "192.168.1.1", "192.168.1.1:80", "vuln2"],
            ["admin", "192.168.1.2", "192.168.1.2:22"]
        ]
        path_scores = scorer.calculate_all_path_scores(paths)
        logger.info(f"✅ Scores de tous les chemins calculés: {len(path_scores)}")
        
        # Obtenir le résumé des risques
        risk_summary = scorer.get_risk_summary()
        logger.info(f"✅ Résumé des risques généré avec succès")
        
        # Obtenir la contribution des nœuds au risque
        node_risk = scorer.get_node_risk_contribution()
        logger.info(f"✅ Contribution des nœuds au risque calculée: {len(node_risk)}")
    except Exception as e:
        logger.error(f"❌ Erreur lors du scoring de risque: {e}")
        return False
    
    logger.info("✅ Test des modules de scoring terminé avec succès")
    return True

def run_reporting_check():
    """
    Teste les modules de reporting.
    """
    logger.info("Test des modules de reporting...")
    
    # Importer les modules
    try:
        from core.reporting.report_generator import ReportGenerator
        import networkx as nx
        from core.analysis.path_analyzer import AttackPathAnalyzer
        
        logger.info("✅ Modules de reporting importés avec succès")
    except ImportError as e:
        logger.error(f"❌ Erreur lors de l'import des modules de reporting: {e}")
        return False
    
    # Créer un graphe de test
    try:
        G = nx.DiGraph()
        
        # Ajouter des nœuds
        G.add_node("192.168.1.1", type="host", os="Windows")
        G.add_node("192.168.1.1:80", type="service", service="http")
        G.add_node("192.168.1.1:22", type="service", service="ssh")
        G.add_node("192.168.1.2", type="host", os="Linux")
        G.add_node("192.168.1.2:22", type="service", service="ssh")
        G.add_node("admin", type="user", admin=True)
        G.add_node("user", type="user", admin=False)
        G.add_node("vuln1", type="vulnerability", name="SQL Injection", severity=8.5)
        G.add_node("vuln2", type="vulnerability", name="XSS", severity=6.5)
        
        # Ajouter des arêtes
        G.add_edge("192.168.1.1", "192.168.1.1:80", label="exposes")
        G.add_edge("192.168.1.1", "192.168.1.1:22", label="exposes")
        G.add_edge("192.168.1.2", "192.168.1.2:22", label="exposes")
        G.add_edge("192.168.1.1:80", "vuln1", label="has_vulnerability")
        G.add_edge("192.168.1.1:80", "vuln2", label="has_vulnerability")
        G.add_edge("user", "192.168.1.1", label="can_access")
        G.add_edge("admin", "192.168.1.2", label="can_access")
        
        logger.info("✅ Graphe de test créé avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la création du graphe de test: {e}")
        return False
    
    # Créer un analyseur
    try:
        analyzer = AttackPathAnalyzer(G)
        analyzer.get_critical_attack_paths()
        logger.info("✅ Analyseur créé avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la création de l'analyseur: {e}")
        return False
    
    # Tester la génération de rapports
    try:
        generator = ReportGenerator(G, analyzer)
        
        # Générer un rapport HTML
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        html_report = os.path.join(reports_dir, 'test_report.html')
        generator.generate_html_report(html_report)
        logger.info(f"✅ Rapport HTML généré: {html_report}")
        
        # Générer un rapport PDF
        try:
            pdf_report = os.path.join(reports_dir, 'test_report.pdf')
            generator.generate_pdf_report(pdf_report)
            logger.info(f"✅ Rapport PDF généré: {pdf_report}")
        except Exception as e:
            logger.warning(f"⚠️ Erreur lors de la génération du rapport PDF (peut nécessiter des dépendances supplémentaires): {e}")
        
        # Obtenir les statistiques du graphe
        stats = generator.get_graph_statistics()
        logger.info(f"✅ Statistiques du graphe générées: {stats['nodes']['total']} nœuds, {stats['edges']['total']} arêtes")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la génération de rapports: {e}")
        return False
    
    logger.info("✅ Test des modules de reporting terminé avec succès")
    return True

def run_integration_check():
    """
    Teste l'intégration des modules.
    """
    logger.info("Test de l'intégration des modules...")
    
    # Importer les modules
    try:
        from core.integrator import AttackPathGraphIntegrator
        
        logger.info("✅ Module d'intégration importé avec succès")
    except ImportError as e:
        logger.error(f"❌ Erreur lors de l'import du module d'intégration: {e}")
        return False
    
    # Créer un intégrateur
    try:
        integrator = AttackPathGraphIntegrator()
        logger.info("✅ Intégrateur créé avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la création de l'intégrateur: {e}")
        return False
    
    # Charger des données de test
    demo_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'demo')
    
    try:
        # Charger des données Nmap
        nmap_file = os.path.join(demo_dir, 'nmap_sample.xml')
        if os.path.exists(nmap_file):
            nmap_data = integrator.load_data('nmap', nmap_file)
            integrator.add_data_to_graph(nmap_data, 'nmap')
            logger.info(f"✅ Données Nmap chargées et ajoutées au graphe")
        else:
            logger.warning(f"⚠️ Fichier d'exemple Nmap non trouvé: {nmap_file}")
        
        # Charger des données BloodHound
        bh_file = os.path.join(demo_dir, 'bloodhound_sample.json')
        if os.path.exists(bh_file):
            bh_data = integrator.load_data('bloodhound', bh_file)
            integrator.add_data_to_graph(bh_data, 'bloodhound')
            logger.info(f"✅ Données BloodHound chargées et ajoutées au graphe")
        else:
            logger.warning(f"⚠️ Fichier d'exemple BloodHound non trouvé: {bh_file}")
        
        # Créer des exemples pour OpenVAS et Metasploit si nécessaire
        if not os.path.exists(os.path.join(demo_dir, 'openvas_sample.xml')):
            create_openvas_sample(os.path.join(demo_dir, 'openvas_sample.xml'))
        
        if not os.path.exists(os.path.join(demo_dir, 'metasploit_sample.json')):
            create_metasploit_sample(os.path.join(demo_dir, 'metasploit_sample.json'))
        
        # Charger des données OpenVAS
        openvas_file = os.path.join(demo_dir, 'openvas_sample.xml')
        if os.path.exists(openvas_file):
            openvas_data = integrator.load_data('openvas', openvas_file)
            integrator.add_data_to_graph(openvas_data, 'openvas')
            logger.info(f"✅ Données OpenVAS chargées et ajoutées au graphe")
        else:
            logger.warning(f"⚠️ Fichier d'exemple OpenVAS non trouvé: {openvas_file}")
        
        # Charger des données Metasploit
        metasploit_file = os.path.join(demo_dir, 'metasploit_sample.json')
        if os.path.exists(metasploit_file):
            metasploit_data = integrator.load_data('metasploit', metasploit_file)
            integrator.add_data_to_graph(metasploit_data, 'metasploit')
            logger.info(f"✅ Données Metasploit chargées et ajoutées au graphe")
        else:
            logger.warning(f"⚠️ Fichier d'exemple Metasploit non trouvé: {metasploit_file}")
    except Exception as e:
        logger.error(f"❌ Erreur lors du chargement des données: {e}")
        return False
    
    # Initialiser les modules
    try:
        analyzer = integrator.initialize_analyzer()
        logger.info("✅ Analyseur initialisé avec succès")
        
        scorer = integrator.initialize_scorer()
        logger.info("✅ Scorer initialisé avec succès")
        
        try:
            mitre = integrator.initialize_mitre_integration()
            logger.info("✅ Intégration MITRE ATT&CK initialisée avec succès")
        except Exception as e:
            logger.warning(f"⚠️ Erreur lors de l'initialisation de l'intégration MITRE ATT&CK: {e}")
        
        report_generator = integrator.initialize_report_generator()
        logger.info("✅ Générateur de rapports initialisé avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'initialisation des modules: {e}")
        return False
    
    # Analyser les chemins d'attaque
    try:
        summary = integrator.analyze_attack_paths()
        logger.info(f"✅ Analyse des chemins d'attaque réussie: {len(summary['paths'])} chemins critiques")
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'analyse des chemins d'attaque: {e}")
        return False
    
    # Générer un rapport
    try:
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        report_path = os.path.join(reports_dir, 'integration_test_report.html')
        integrator.generate_report(report_path)
        logger.info(f"✅ Rapport généré: {report_path}")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la génération du rapport: {e}")
        return False
    
    logger.info("✅ Test de l'intégration des modules terminé avec succès")
    return True

def create_openvas_sample(file_path):
    """
    Crée un fichier d'exemple OpenVAS.
    
    Args:
        file_path (str): Chemin du fichier à créer
    """
    content = """<?xml version="1.0" encoding="UTF-8"?>
<openvas-report>
  <host>
    <ip>192.168.1.1</ip>
    <hostname>server1.example.com</hostname>
    <os>Windows Server 2019</os>
    <result id="vuln-001">
      <name>SQL Injection Vulnerability</name>
      <threat>High</threat>
      <severity>8.5</severity>
    </result>
    <result id="vuln-002">
      <name>Cross-Site Scripting</name>
      <threat>Medium</threat>
      <severity>6.5</severity>
    </result>
  </host>
  <host>
    <ip>192.168.1.2</ip>
    <hostname>server2.example.com</hostname>
    <os>Ubuntu 20.04</os>
    <result id="vuln-003">
      <name>Outdated OpenSSH</name>
      <threat>Medium</threat>
      <severity>5.5</severity>
    </result>
  </host>
</openvas-report>"""
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    logger.info(f"Fichier d'exemple OpenVAS créé: {file_path}")

def create_metasploit_sample(file_path):
    """
    Crée un fichier d'exemple Metasploit.
    
    Args:
        file_path (str): Chemin du fichier à créer
    """
    content = """{
  "hosts": [
    {
      "address": "192.168.1.1",
      "name": "server1.example.com",
      "os_name": "Windows Server 2019"
    },
    {
      "address": "192.168.1.2",
      "name": "server2.example.com",
      "os_name": "Ubuntu 20.04"
    }
  ],
  "vulns": [
    {
      "id": "msf-vuln-001",
      "host": "192.168.1.1",
      "name": "MS17-010 EternalBlue",
      "info": "SMB Remote Code Execution Vulnerability",
      "severity": 9.5
    },
    {
      "id": "msf-vuln-002",
      "host": "192.168.1.2",
      "name": "Apache Struts RCE",
      "info": "Remote Code Execution Vulnerability",
      "severity": 8.0
    }
  ],
  "modules": [
    {
      "id": "msf-module-001",
      "name": "EternalBlue Exploit",
      "description": "Exploit for MS17-010 vulnerability",
      "rank": "excellent",
      "references": ["msf-vuln-001"]
    },
    {
      "id": "msf-module-002",
      "name": "Struts RCE Exploit",
      "description": "Exploit for Apache Struts vulnerability",
      "rank": "good",
      "references": ["msf-vuln-002"]
    }
  ]
}"""
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    logger.info(f"Fichier d'exemple Metasploit créé: {file_path}")

def main():
    """
    Fonction principale.
    """
    parser = argparse.ArgumentParser(description="Test des modules AttackPathGraph")
    parser.add_argument("--all", action="store_true", help="Tester tous les modules")
    parser.add_argument("--parsers", action="store_true", help="Tester les modules de parsing")
    parser.add_argument("--analysis", action="store_true", help="Tester les modules d'analyse")
    parser.add_argument("--scoring", action="store_true", help="Tester les modules de scoring")
    parser.add_argument("--reporting", action="store_true", help="Tester les modules de reporting")
    parser.add_argument("--integration", action="store_true", help="Tester l'intégration des modules")
    
    args = parser.parse_args()
    
    # Si aucun argument n'est spécifié, tester tous les modules
    if not any(vars(args).values()):
        args.all = True
    
    results = {}
    
    if args.all or args.parsers:
        results["parsers"] = run_parsers_check()
    
    if args.all or args.analysis:
        results["analysis"] = run_analysis_check()
    
    if args.all or args.scoring:
        results["scoring"] = run_scoring_check()
    
    if args.all or args.reporting:
        results["reporting"] = run_reporting_check()
    
    if args.all or args.integration:
        results["integration"] = run_integration_check()
    
    # Afficher le résumé
    print("\n=== Résumé des tests ===")
    all_success = True
    for module, success in results.items():
        status = "✅ Succès" if success else "❌ Échec"
        print(f"{module}: {status}")
        all_success = all_success and success
    
    if all_success:
        print("\n✅ Tous les tests ont réussi!")
        return 0
    else:
        print("\n❌ Certains tests ont échoué. Consultez les logs pour plus de détails.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
