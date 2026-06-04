#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de revue de sécurité pour AttackPathGraph.
Ce module permet d'effectuer une analyse de sécurité sur le code du projet.
"""

import os
import re
import sys
import logging
import json
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityReviewer:
    """
    Classe pour la revue de sécurité du code.
    """
    
    def __init__(self, project_dir):
        """
        Initialise le reviewer de sécurité.
        
        Args:
            project_dir (str): Répertoire du projet à analyser
        """
        self.project_dir = Path(project_dir)
        self.issues = []
        self.report = {
            'summary': {
                'total_files': 0,
                'total_issues': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'issues': []
        }
    
    def run_analysis(self):
        """
        Exécute l'analyse de sécurité complète.
        
        Returns:
            dict: Rapport d'analyse
        """
        logger.info(f"Démarrage de l'analyse de sécurité pour {self.project_dir}")
        
        # Vérifier les dépendances
        self._check_dependencies()
        
        # Analyser les fichiers Python
        self._analyze_python_files()
        
        # Analyser les fichiers JavaScript
        self._analyze_js_files()
        
        # Analyser les fichiers HTML
        self._analyze_html_files()
        
        # Analyser les fichiers de configuration
        self._analyze_config_files()
        
        # Générer le rapport
        self._generate_report()
        
        logger.info(f"Analyse terminée: {self.report['summary']['total_issues']} problèmes trouvés")
        return self.report
    
    def _check_dependencies(self):
        """
        Vérifie les dépendances du projet pour des vulnérabilités connues.
        """
        requirements_file = self.project_dir / 'requirements.txt'
        
        if requirements_file.exists():
            logger.info("Vérification des dépendances Python...")
            
            try:
                # Lire les dépendances
                with open(requirements_file, 'r') as f:
                    dependencies = f.readlines()
                
                # Vérifier chaque dépendance
                for dep in dependencies:
                    dep = dep.strip()
                    if not dep or dep.startswith('#'):
                        continue
                    
                    # Vérifier les versions obsolètes ou vulnérables
                    if 'flask' in dep.lower() and not self._check_version_secure(dep, '2.0.0'):
                        self._add_issue(
                            'dependency',
                            'high',
                            f"Version obsolète de Flask: {dep}",
                            "Utiliser Flask 2.0.0 ou supérieur pour éviter les vulnérabilités connues",
                            requirements_file
                        )
                    
                    if 'jinja2' in dep.lower() and not self._check_version_secure(dep, '3.0.0'):
                        self._add_issue(
                            'dependency',
                            'high',
                            f"Version obsolète de Jinja2: {dep}",
                            "Utiliser Jinja2 3.0.0 ou supérieur pour éviter les vulnérabilités connues",
                            requirements_file
                        )
                    
                    if 'werkzeug' in dep.lower() and not self._check_version_secure(dep, '2.0.0'):
                        self._add_issue(
                            'dependency',
                            'high',
                            f"Version obsolète de Werkzeug: {dep}",
                            "Utiliser Werkzeug 2.0.0 ou supérieur pour éviter les vulnérabilités connues",
                            requirements_file
                        )
                    
                    if 'py2neo' in dep.lower() and not self._check_version_secure(dep, '2021.0.0'):
                        self._add_issue(
                            'dependency',
                            'medium',
                            f"Version potentiellement obsolète de py2neo: {dep}",
                            "Vérifier la compatibilité avec les versions récentes de Neo4j",
                            requirements_file
                        )
                    
                    if 'requests' in dep.lower() and not self._check_version_secure(dep, '2.25.0'):
                        self._add_issue(
                            'dependency',
                            'medium',
                            f"Version obsolète de Requests: {dep}",
                            "Utiliser Requests 2.25.0 ou supérieur pour éviter les vulnérabilités connues",
                            requirements_file
                        )
            
            except Exception as e:
                logger.error(f"Erreur lors de la vérification des dépendances: {e}")
    
    def _check_version_secure(self, dependency, min_version):
        """
        Vérifie si la version d'une dépendance est sécurisée.
        
        Args:
            dependency (str): Dépendance avec version
            min_version (str): Version minimale sécurisée
            
        Returns:
            bool: True si la version est sécurisée, False sinon
        """
        # Extraire le nom et la version
        parts = dependency.split('==')
        if len(parts) < 2:
            return False
        
        version = parts[1]
        
        # Comparer les versions
        try:
            current_parts = [int(x) for x in version.split('.')]
            min_parts = [int(x) for x in min_version.split('.')]
            
            for i in range(max(len(current_parts), len(min_parts))):
                current = current_parts[i] if i < len(current_parts) else 0
                minimum = min_parts[i] if i < len(min_parts) else 0
                
                if current > minimum:
                    return True
                elif current < minimum:
                    return False
            
            return True
        except ValueError:
            return False
    
    def _analyze_python_files(self):
        """
        Analyse les fichiers Python pour des problèmes de sécurité.
        """
        logger.info("Analyse des fichiers Python...")
        
        # Trouver tous les fichiers Python
        python_files = list(self.project_dir.glob('**/*.py'))
        self.report['summary']['total_files'] += len(python_files)
        
        # Patterns de vulnérabilités
        patterns = {
            'sql_injection': {
                'pattern': r'execute\s*\(\s*[\'"][^\'")]*%|execute\s*\(\s*[\'"][^\'")]*\+|execute\s*\(\s*f[\'"]',
                'severity': 'critical',
                'message': "Possible injection SQL",
                'recommendation': "Utiliser des requêtes paramétrées ou des ORM"
            },
            'command_injection': {
                'pattern': r'os\.system\s*\(|subprocess\.call\s*\(|subprocess\.Popen\s*\(|eval\s*\(',
                'severity': 'critical',
                'message': "Possible injection de commande",
                'recommendation': "Éviter d'exécuter des commandes système avec des entrées utilisateur"
            },
            'hardcoded_credentials': {
                'pattern': r'password\s*=\s*[\'"][^\'"]+[\'"]|api_key\s*=\s*[\'"][^\'"]+[\'"]|secret\s*=\s*[\'"][^\'"]+[\'"]',
                'severity': 'high',
                'message': "Identifiants codés en dur",
                'recommendation': "Utiliser des variables d'environnement ou un gestionnaire de secrets"
            },
            'insecure_deserialization': {
                'pattern': r'pickle\.loads|yaml\.load\s*\([^,]',
                'severity': 'high',
                'message': "Désérialisation non sécurisée",
                'recommendation': "Utiliser yaml.safe_load() ou d'autres méthodes sécurisées"
            },
            'debug_enabled': {
                'pattern': r'debug\s*=\s*True',
                'severity': 'medium',
                'message': "Mode debug activé",
                'recommendation': "Désactiver le mode debug en production"
            },
            'weak_crypto': {
                'pattern': r'import\s+md5|hashlib\.md5|import\s+sha1|hashlib\.sha1',
                'severity': 'medium',
                'message': "Utilisation d'algorithmes cryptographiques faibles",
                'recommendation': "Utiliser des algorithmes plus sécurisés comme SHA-256 ou SHA-3"
            },
            'insecure_random': {
                'pattern': r'import\s+random|from\s+random\s+import',
                'severity': 'low',
                'message': "Utilisation potentielle de générateur de nombres aléatoires non cryptographique",
                'recommendation': "Utiliser secrets.token_bytes() pour la génération de tokens sécurisés"
            }
        }
        
        # Analyser chaque fichier
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for issue_type, config in patterns.items():
                    matches = re.finditer(config['pattern'], content)
                    for match in matches:
                        line_no = content[:match.start()].count('\n') + 1
                        self._add_issue(
                            issue_type,
                            config['severity'],
                            config['message'],
                            config['recommendation'],
                            file_path,
                            line_no
                        )
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de {file_path}: {e}")
    
    def _analyze_js_files(self):
        """
        Analyse les fichiers JavaScript pour des problèmes de sécurité.
        """
        logger.info("Analyse des fichiers JavaScript...")
        
        # Trouver tous les fichiers JavaScript
        js_files = list(self.project_dir.glob('**/*.js'))
        self.report['summary']['total_files'] += len(js_files)
        
        # Patterns de vulnérabilités
        patterns = {
            'xss': {
                'pattern': r'innerHTML\s*=|document\.write\s*\(',
                'severity': 'high',
                'message': "Possible vulnérabilité XSS",
                'recommendation': "Utiliser textContent ou innerText, ou échapper les entrées utilisateur"
            },
            'eval_usage': {
                'pattern': r'eval\s*\(',
                'severity': 'high',
                'message': "Utilisation de eval()",
                'recommendation': "Éviter d'utiliser eval() qui peut exécuter du code arbitraire"
            },
            'hardcoded_credentials': {
                'pattern': r'password\s*[:=]\s*[\'"][^\'"]+[\'"]|apiKey\s*[:=]\s*[\'"][^\'"]+[\'"]|secret\s*[:=]\s*[\'"][^\'"]+[\'"]',
                'severity': 'high',
                'message': "Identifiants codés en dur",
                'recommendation': "Utiliser des variables d'environnement ou un gestionnaire de secrets"
            },
            'insecure_random': {
                'pattern': r'Math\.random\s*\(',
                'severity': 'medium',
                'message': "Utilisation de Math.random() pour la sécurité",
                'recommendation': "Utiliser window.crypto.getRandomValues() pour la génération de valeurs aléatoires sécurisées"
            }
        }
        
        # Analyser chaque fichier
        for file_path in js_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for issue_type, config in patterns.items():
                    matches = re.finditer(config['pattern'], content)
                    for match in matches:
                        line_no = content[:match.start()].count('\n') + 1
                        self._add_issue(
                            issue_type,
                            config['severity'],
                            config['message'],
                            config['recommendation'],
                            file_path,
                            line_no
                        )
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de {file_path}: {e}")
    
    def _analyze_html_files(self):
        """
        Analyse les fichiers HTML pour des problèmes de sécurité.
        """
        logger.info("Analyse des fichiers HTML...")
        
        # Trouver tous les fichiers HTML
        html_files = list(self.project_dir.glob('**/*.html'))
        self.report['summary']['total_files'] += len(html_files)
        
        # Patterns de vulnérabilités
        patterns = {
            'csp_missing': {
                'pattern': r'<meta\s+http-equiv=[\'"]Content-Security-Policy[\'"]',
                'severity': 'medium',
                'message': "Absence de Content Security Policy",
                'recommendation': "Ajouter une politique CSP pour limiter les sources de contenu",
                'inverse': True
            },
            'inline_script': {
                'pattern': r'<script>[^<]+</script>|<script\s+[^>]*>[^<]+</script>',
                'severity': 'low',
                'message': "Script inline détecté",
                'recommendation': "Déplacer les scripts dans des fichiers externes"
            },
            'inline_style': {
                'pattern': r'style=[\'"][^\'"]+[\'"]',
                'severity': 'info',
                'message': "Style inline détecté",
                'recommendation': "Déplacer les styles dans des fichiers CSS externes"
            }
        }
        
        # Analyser chaque fichier
        for file_path in html_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for issue_type, config in patterns.items():
                    inverse = config.get('inverse', False)
                    matches = re.finditer(config['pattern'], content)
                    
                    if inverse:
                        # Pour les patterns inversés (absence de quelque chose)
                        if not list(matches):
                            self._add_issue(
                                issue_type,
                                config['severity'],
                                config['message'],
                                config['recommendation'],
                                file_path
                            )
                    else:
                        # Pour les patterns normaux
                        for match in matches:
                            line_no = content[:match.start()].count('\n') + 1
                            self._add_issue(
                                issue_type,
                                config['severity'],
                                config['message'],
                                config['recommendation'],
                                file_path,
                                line_no
                            )
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de {file_path}: {e}")
    
    def _analyze_config_files(self):
        """
        Analyse les fichiers de configuration pour des problèmes de sécurité.
        """
        logger.info("Analyse des fichiers de configuration...")
        
        # Trouver les fichiers de configuration
        config_files = list(self.project_dir.glob('**/*.json')) + list(self.project_dir.glob('**/*.yaml')) + list(self.project_dir.glob('**/*.yml'))
        self.report['summary']['total_files'] += len(config_files)
        
        # Patterns de vulnérabilités
        patterns = {
            'hardcoded_credentials': {
                'pattern': r'password[\'"]?\s*:\s*[\'"][^\'"]+[\'"]|apiKey[\'"]?\s*:\s*[\'"][^\'"]+[\'"]|secret[\'"]?\s*:\s*[\'"][^\'"]+[\'"]',
                'severity': 'high',
                'message': "Identifiants codés en dur",
                'recommendation': "Utiliser des variables d'environnement ou un gestionnaire de secrets"
            },
            'insecure_config': {
                'pattern': r'debug[\'"]?\s*:\s*true|ssl[\'"]?\s*:\s*false|verify[\'"]?\s*:\s*false',
                'severity': 'medium',
                'message': "Configuration non sécurisée",
                'recommendation': "Vérifier les paramètres de sécurité en production"
            }
        }
        
        # Analyser chaque fichier
        for file_path in config_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for issue_type, config in patterns.items():
                    matches = re.finditer(config['pattern'], content)
                    for match in matches:
                        line_no = content[:match.start()].count('\n') + 1
                        self._add_issue(
                            issue_type,
                            config['severity'],
                            config['message'],
                            config['recommendation'],
                            file_path,
                            line_no
                        )
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de {file_path}: {e}")
    
    def _add_issue(self, issue_type, severity, message, recommendation, file_path, line_no=None):
        """
        Ajoute un problème au rapport.
        
        Args:
            issue_type (str): Type de problème
            severity (str): Sévérité du problème (critical, high, medium, low, info)
            message (str): Description du problème
            recommendation (str): Recommandation pour résoudre le problème
            file_path (str): Chemin du fichier concerné
            line_no (int, optional): Numéro de ligne. Par défaut None.
        """
        issue = {
            'type': issue_type,
            'severity': severity,
            'message': message,
            'recommendation': recommendation,
            'file': str(file_path.relative_to(self.project_dir)),
            'line': line_no
        }
        
        self.issues.append(issue)
        self.report['summary']['total_issues'] += 1
        self.report['summary'][severity] += 1
    
    def _generate_report(self):
        """
        Génère le rapport final.
        """
        # Trier les problèmes par sévérité
        severity_order = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'info': 4
        }
        
        sorted_issues = sorted(self.issues, key=lambda x: (severity_order.get(x['severity'], 999), x['file'], x.get('line', 0)))
        self.report['issues'] = sorted_issues
    
    def save_report(self, output_path):
        """
        Sauvegarde le rapport au format JSON.
        
        Args:
            output_path (str): Chemin de sortie pour le rapport
            
        Returns:
            str: Chemin du rapport sauvegardé
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=2)
        
        logger.info(f"Rapport sauvegardé: {output_path}")
        return output_path
    
    def print_summary(self):
        """
        Affiche un résumé du rapport.
        """
        summary = self.report['summary']
        
        print("\n=== Résumé de l'analyse de sécurité ===")
        print(f"Fichiers analysés: {summary['total_files']}")
        print(f"Problèmes trouvés: {summary['total_issues']}")
        print(f"  - Critique: {summary['critical']}")
        print(f"  - Élevé: {summary['high']}")
        print(f"  - Moyen: {summary['medium']}")
        print(f"  - Faible: {summary['low']}")
        print(f"  - Info: {summary['info']}")
        
        if summary['critical'] > 0 or summary['high'] > 0:
            print("\n⚠️ Des problèmes critiques ou élevés ont été détectés. Veuillez consulter le rapport complet.")
        elif summary['total_issues'] > 0:
            print("\n⚠️ Des problèmes ont été détectés. Veuillez consulter le rapport complet.")
        else:
            print("\n✅ Aucun problème détecté.")


def main():
    """
    Fonction principale.
    """
    if len(sys.argv) < 2:
        print("Usage: python security_review.py <project_dir> [output_path]")
        sys.exit(1)
    
    project_dir = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(project_dir, 'security_report.json')
    
    reviewer = SecurityReviewer(project_dir)
    reviewer.run_analysis()
    reviewer.save_report(output_path)
    reviewer.print_summary()


if __name__ == "__main__":
    main()
