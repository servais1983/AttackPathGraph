![image](attackpath.png)

# 🧠 AttackPathGraph - Plateforme avancée d'analyse des chemins d'attaque

<p align="center">
  <img src="https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/Neo4j-4.4+-4581C3?style=for-the-badge&logo=neo4j&logoColor=white" alt="Neo4j 4.4+"/>
  <img src="https://img.shields.io/badge/MITRE_ATT&CK-v12-E8383B?style=for-the-badge&logo=mitre&logoColor=white" alt="MITRE ATT&CK"/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT"/>
</p>

<p align="center">
  <b>Plateforme professionnelle d'analyse et de visualisation des chemins d'attaque pour la cybersécurité</b><br>
  <sub>🔍 Multi-sources | 🔄 Analyse avancée | 🎯 Scoring de risque | 📊 Rapports professionnels | 🌐 Interface web</sub>
</p>

---

## 📋 Description

**AttackPathGraph** est une plateforme professionnelle conçue pour **analyser, visualiser et prioriser les chemins d'attaque potentiels** dans les infrastructures informatiques. Elle intègre des données provenant de multiples sources (scanners de vulnérabilités, outils de pentest, analyses Active Directory) pour construire un graphe orienté représentant les chemins d'attaque possibles, calculer leur criticité et générer des rapports détaillés.

Cette plateforme répond aux besoins des équipes de sécurité offensive et défensive en offrant une vision claire et actionnable des vulnérabilités et des chemins d'attaque critiques, alignée avec le framework MITRE ATT&CK.

> ⚠️ **Avertissement** : Cet outil est destiné exclusivement à des fins légitimes telles que les tests de pénétration, la formation à la sensibilisation à la sécurité et l'évaluation des vulnérabilités. Toute utilisation non autorisée est illégale et contraire à l'éthique.

### 🔍 Fonctionnalités principales

- **Intégration multi-sources** :
  - 📄 **Nmap** : Import des résultats de scan au format XML
  - 🔗 **BloodHound** : Import des relations AD au format JSON
  - 🔍 **OpenVAS** : Import des vulnérabilités au format XML
  - 🛠️ **Metasploit** : Import des données d'exploitation au format JSON/XML

- **Analyse avancée** :
  - 🔄 **Détection automatique des chemins d'attaque critiques**
  - 📊 **Scoring de risque** basé sur la sévérité des vulnérabilités et la complexité des chemins
  - 🎯 **Mapping MITRE ATT&CK** pour identifier les techniques d'attaque et les mitigations

- **Visualisation et reporting** :
  - 🌐 **Interface web interactive** pour explorer les graphes d'attaque
  - 📑 **Rapports HTML/PDF détaillés** pour documentation et présentation
  - 📊 **Visualisation ASCII** pour affichage rapide dans le terminal
  - 🗃️ **Export Neo4j** pour analyses avancées et intégration avec d'autres outils

- **Sécurité et conformité** :
  - 🔒 **Revue DevSecOps intégrée** pour garantir la sécurité du code
  - 🛡️ **Gestion sécurisée des identifiants** via variables d'environnement
  - ✅ **Tests unitaires et d'intégration** pour assurer la fiabilité

## ⚙️ Installation

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/AttackPathGraph.git
cd AttackPathGraph

# Rendre le script d'installation exécutable
chmod +x install.sh

# Lancer l'installation
./install.sh
```

L'installation met en place les dépendances nécessaires (Python, NetworkX, py2neo, Flask, etc.) et prépare l'environnement d'exécution.

### Dépendances principales

- Python 3.8+
- NetworkX
- py2neo
- Flask (pour l'interface web)
- Jinja2 (pour les templates de rapports)
- WeasyPrint (pour la génération de PDF)
- Requests (pour l'intégration MITRE ATT&CK)

## 🛠️ Commandes

### Interface en ligne de commande

```bash
python3 pentest_graph.py [OPTIONS]
```

| Option | Description | 
|----------|-------------|
| `--nmap FILE` | Importe un fichier XML généré par Nmap |
| `--bh FILE` | Importe un fichier JSON généré par BloodHound |
| `--openvas FILE` | Importe un fichier XML généré par OpenVAS |
| `--metasploit FILE` | Importe un fichier JSON/XML généré par Metasploit |
| `--ascii` | Affiche une représentation ASCII du graphe dans le terminal |
| `--neo4j` | Exporte le graphe vers une base de données Neo4j |
| `--analyze` | Effectue une analyse des chemins d'attaque critiques |
| `--score` | Calcule les scores de risque pour les chemins d'attaque |
| `--mitre` | Effectue un mapping avec les techniques MITRE ATT&CK |
| `--report FILE` | Génère un rapport détaillé (HTML ou PDF selon l'extension) |
| `--web` | Lance l'interface web de visualisation |

### Interface web

```bash
python3 web_interface.py
```

L'interface web est accessible par défaut à l'adresse `http://localhost:5000`.

## 🚀 Exemples d'utilisation

### Analyse complète avec génération de rapport

```bash
python3 pentest_graph.py --nmap scans/nmap_results.xml --openvas scans/openvas_results.xml --analyze --score --mitre --report reports/security_assessment.pdf
```

Cette commande va:
1. Charger les données Nmap et OpenVAS
2. Analyser les chemins d'attaque critiques
3. Calculer les scores de risque
4. Effectuer un mapping avec MITRE ATT&CK
5. Générer un rapport PDF détaillé

### Lancement de l'interface web avec données préchargées

```bash
python3 pentest_graph.py --nmap scans/nmap_results.xml --bh scans/bloodhound_results.json --web
```

Cette commande va:
1. Charger les données Nmap et BloodHound
2. Lancer l'interface web pour explorer le graphe d'attaque

### Export vers Neo4j pour analyses avancées

```bash
python3 pentest_graph.py --nmap scans/nmap_results.xml --openvas scans/openvas_results.xml --metasploit scans/metasploit_results.json --neo4j
```

Cette commande va:
1. Charger les données de multiples sources
2. Exporter le graphe complet vers Neo4j pour des analyses personnalisées

## 🗂️ Architecture du projet

```
attackpathgraph/
├── core/                  # Modules principaux
│   ├── parsers/           # Parseurs pour différentes sources de données
│   │   ├── parsers.py     # Parseurs de base (Nmap, BloodHound)
│   │   ├── openvas_parser.py  # Parseur OpenVAS
│   │   └── metasploit_parser.py  # Parseur Metasploit
│   ├── analysis/          # Modules d'analyse
│   │   ├── path_analyzer.py  # Analyse des chemins d'attaque
│   │   └── mitre_attack.py  # Intégration MITRE ATT&CK
│   ├── scoring/           # Modules de scoring
│   │   └── risk_scorer.py  # Calcul des scores de risque
│   ├── reporting/         # Modules de génération de rapports
│   │   └── report_generator.py  # Génération de rapports HTML/PDF
│   ├── web/               # Interface web
│   │   └── web_interface.py  # Serveur web Flask
│   ├── security/          # Modules de sécurité
│   │   └── security_review.py  # Revue de sécurité DevSecOps
│   ├── graph_engine.py    # Moteur de graphe (NetworkX, Neo4j)
│   └── integrator.py      # Intégrateur de modules
├── templates/             # Templates pour les rapports et l'interface web
├── static/                # Ressources statiques pour l'interface web
│   ├── css/               # Feuilles de style
│   └── js/                # Scripts JavaScript
├── demo/                  # Fichiers d'exemple
│   ├── nmap_sample.xml
│   ├── bloodhound_sample.json
│   ├── openvas_sample.xml
│   └── metasploit_sample.json
├── tests/                 # Tests unitaires et d'intégration
│   └── test_modules.py    # Tests des modules
├── reports/               # Rapports générés
├── pentest_graph.py       # Point d'entrée principal
├── web_interface.py       # Point d'entrée de l'interface web
├── requirements.txt       # Dépendances Python
├── install.sh             # Script d'installation
└── README.md              # Documentation
```

## 📊 Fonctionnalités détaillées

### Intégration multi-sources

AttackPathGraph peut intégrer des données provenant de multiples sources pour construire un graphe d'attaque complet:

- **Nmap**: Import des hôtes, ports et services détectés
- **BloodHound**: Import des relations entre utilisateurs, groupes et systèmes Active Directory
- **OpenVAS**: Import des vulnérabilités détectées avec leur sévérité CVSS
- **Metasploit**: Import des vulnérabilités exploitables et des modules d'exploitation

Cette approche multi-sources permet d'obtenir une vision complète de l'infrastructure et des vulnérabilités.

### Analyse des chemins d'attaque

Le module d'analyse identifie automatiquement:

- Les points d'entrée potentiels (services exposés, utilisateurs externes)
- Les actifs critiques (serveurs de domaine, bases de données, utilisateurs privilégiés)
- Les chemins d'attaque possibles entre les points d'entrée et les actifs critiques

L'algorithme prend en compte la complexité des chemins, les privilèges requis et la sévérité des vulnérabilités pour identifier les chemins les plus critiques.

### Scoring de risque

Le module de scoring calcule un score de risque pour chaque chemin d'attaque en fonction de:

- La sévérité des vulnérabilités (basée sur CVSS)
- La complexité du chemin (nombre d'étapes)
- La criticité des actifs ciblés
- La probabilité d'exploitation

Les scores sont normalisés sur une échelle de 0 à 10 et catégorisés en niveaux de risque (Critique, Élevé, Moyen, Faible, Info).

### Intégration MITRE ATT&CK

Le module d'intégration MITRE ATT&CK:

- Mappe les vulnérabilités et les chemins d'attaque aux techniques MITRE ATT&CK
- Identifie les tactiques utilisées dans les chemins d'attaque
- Suggère des mitigations basées sur les techniques identifiées
- Fournit des informations sur les groupes d'attaquants connus utilisant ces techniques

### Génération de rapports

Le module de génération de rapports produit des rapports détaillés au format HTML ou PDF, incluant:

- Un résumé exécutif des risques identifiés
- Une visualisation des chemins d'attaque critiques
- Des détails sur chaque vulnérabilité et chemin d'attaque
- Des recommandations de mitigation basées sur MITRE ATT&CK
- Des statistiques et métriques de risque

### Interface web

L'interface web offre une expérience interactive pour:

- Visualiser le graphe d'attaque complet
- Explorer les chemins d'attaque critiques
- Filtrer les nœuds par type et niveau de risque
- Afficher les détails des nœuds et des relations
- Générer des rapports à la demande

## 🔒 Sécurité et DevSecOps

AttackPathGraph intègre des pratiques DevSecOps pour garantir sa propre sécurité:

- **Revue de code automatisée**: Détection des vulnérabilités potentielles dans le code
- **Gestion sécurisée des identifiants**: Utilisation de variables d'environnement pour les identifiants Neo4j
- **Validation des entrées**: Protection contre les injections et autres vulnérabilités
- **Tests de sécurité**: Vérification de la robustesse des composants

## 🧪 Tests

AttackPathGraph inclut une suite de tests unitaires et d'intégration pour valider le fonctionnement des modules:

```bash
# Exécuter tous les tests
python3 tests/test_modules.py --all

# Tester des modules spécifiques
python3 tests/test_modules.py --parsers --analysis
```

## 🔄 Intégration avec d'autres outils

AttackPathGraph peut s'intégrer avec d'autres outils de sécurité:

- **Neo4j**: Export du graphe pour des analyses personnalisées
- **MITRE ATT&CK**: Mapping des techniques et tactiques
- **Systèmes de tickets**: Export des vulnérabilités au format CSV/JSON
- **Dashboards de sécurité**: Intégration via API REST

## 🤝 Contribuer

Les contributions sont les bienvenues ! Voici comment vous pouvez contribuer:

1. **Ajouter de nouveaux parseurs** pour d'autres outils de sécurité
2. **Améliorer les algorithmes d'analyse** des chemins d'attaque
3. **Enrichir l'interface web** avec de nouvelles fonctionnalités
4. **Développer de nouveaux formats de rapport** pour différents cas d'usage
5. **Ajouter des tests** pour améliorer la couverture

Pour contribuer, veuillez suivre ces étapes:
1. Forker le dépôt
2. Créer une branche pour votre fonctionnalité (`git checkout -b feature/ma-fonctionnalite`)
3. Committer vos changements (`git commit -m 'Ajout de ma fonctionnalité'`)
4. Pousser vers la branche (`git push origin feature/ma-fonctionnalite`)
5. Ouvrir une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

---

<p align="center">
  <sub>🔐 Développé pour révolutionner l'analyse de sécurité par la visualisation avancée des chemins d'attaque 🛡️</sub>
</p>
