![image](https://github.com/user-attachments/assets/54483fa3-b5db-4770-8047-8ca90df8ea06)


# 🧠 AttackPathGraph CLI

<p align="center">
  <img src="https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT"/>
</p>

<p align="center">
  <b>Visualisation en graphe des chemins d'attaque réels pour les pentests Red Team</b><br>
  <sub>🔍 Nmap | 🔄 BloodHound | 🎯 Analyse de graphes | 📊 Neo4j</sub>
</p>

---

## 📋 Description

**AttackPathGraph** est un outil en ligne de commande conçu pour **visualiser les chemins d'attaque potentiels** découverts lors de tests d'intrusion. Il permet d'importer des données de reconnaissance (Nmap) et des relations entre utilisateurs et systèmes (BloodHound) pour construire un graphe orienté représentant les chemins d'attaque possibles.

> ⚠️ **Avertissement** : Cet outil est destiné exclusivement à des fins légitimes telles que les tests de pénétration, la formation à la sensibilisation à la sécurité et l'évaluation des vulnérabilités. Toute utilisation non autorisée est illégale et contraire à l'éthique.

### 🔍 Fonctionnalités principales

- 📄 **Intégration Nmap** : Import des résultats de scan au format XML
- 🔗 **Intégration BloodHound** : Import des relations AD au format JSON
- 🔄 **Graphe orienté** : Représentation des relations entre nœuds
- 📊 **Visualisation ASCII** : Affichage rapide dans le terminal
- 🗃️ **Export Neo4j** : Stockage du graphe dans une base Neo4j
- 🔄 **Extension facile** : Support pour d'autres outils de pentest

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

L'installation met en place les dépendances nécessaires (Python, NetworkX, py2neo) et prépare l'environnement d'exécution sur Kali Linux.

## 🛠️ Commandes

| Option | Description | 
|----------|-------------|
| `--nmap FILE` | Importe un fichier XML généré par Nmap |
| `--bh FILE` | Importe un fichier JSON généré par BloodHound |
| `--ascii` | Affiche une représentation ASCII du graphe dans le terminal |
| `--neo4j` | Exporte le graphe vers une base de données Neo4j |

## 🚀 Exemple d'utilisation

### Visualisation ASCII

```bash
python3 pentest_graph.py --ascii --nmap demo/nmap_sample.xml --bh demo/bloodhound_sample.json
```

Cette commande va:
1. Charger les données Nmap (hôtes et services)
2. Charger les données BloodHound (relations utilisateurs/systèmes)
3. Afficher une représentation ASCII du graphe dans le terminal

### Export vers Neo4j

```bash
python3 pentest_graph.py --neo4j --nmap demo/nmap_sample.xml --bh demo/bloodhound_sample.json
```

⚠️ Neo4j doit être installé et lancé sur `bolt://localhost:7687` (ou modifier les paramètres dans le code).

## 🗂️ Structure du projet

```
attackpathgraph/
├── core/              # Modules principaux
│   ├── graph_engine.py # Moteur de graphe (NetworkX, Neo4j)
│   └── parsers.py     # Parseurs (Nmap XML, BloodHound JSON)
├── demo/              # Fichiers d'exemple
│   ├── nmap_sample.xml
│   └── bloodhound_sample.json
├── pentest_graph.py   # Point d'entrée principal
├── requirements.txt   # Dépendances Python
├── install.sh         # Script d'installation
└── README.md          # Documentation
```

## 📈 Fonctionnalités à venir

- [ ] Support pour d'autres formats d'import (OpenVAS, Metasploit, etc.)
- [ ] Détection automatique des chemins d'attaque critiques
- [ ] Interface web pour visualiser les graphes
- [ ] Génération de rapports détaillés en HTML/PDF
- [ ] Calcul des scores de risque sur les chemins d'attaque
- [ ] Intégration avec d'autres outils (MITRE ATT&CK, etc.)

## 🔒 Sécurité et Éthique

Ce projet est conçu pour des **tests de sécurité légitimes** et pour **visualiser les chemins d'attaque**. Utilisez-le uniquement avec une autorisation explicite dans le cadre de :

- ✅ Tests de pénétration autorisés
- ✅ Évaluations de sécurité internes
- ✅ Exercises Red Team
- ✅ Formations de sensibilisation

## 🤝 Contribuer

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou à soumettre une pull request pour améliorer l'outil.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

---

<p align="center">
  <sub>🔐 Développé pour améliorer la sécurité des réseaux par la visualisation des chemins d'attaque 🛡️</sub>
</p>
