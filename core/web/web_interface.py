#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'interface web pour AttackPathGraph.
Ce module permet de visualiser les graphes d'attaque via une interface web.
"""

import os
import logging
import threading
import webbrowser
import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory

logger = logging.getLogger(__name__)


def _file_contains(path, marker):
    try:
        with open(path, 'r', encoding='utf-8') as file:
            return marker in file.read()
    except OSError:
        return False


class WebInterface:
    """
    Classe pour l'interface web de visualisation des graphes d'attaque.
    """
    
    def __init__(self, graph=None, analyzer=None, scorer=None, mitre_integration=None):
        """
        Initialise l'interface web.
        
        Args:
            graph (nx.DiGraph, optional): Graphe d'attaque NetworkX
            analyzer (AttackPathAnalyzer, optional): Analyseur de chemins d'attaque
            scorer (RiskScorer, optional): Calculateur de scores de risque
            mitre_integration (MitreAttackIntegration, optional): Intégration MITRE ATT&CK
        """
        self.graph = graph
        self.analyzer = analyzer
        self.scorer = scorer
        self.mitre_integration = mitre_integration
        
        # Créer les répertoires nécessaires
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.template_dir = os.path.join(self.base_dir, '..', '..', 'templates')
        self.static_dir = os.path.join(self.base_dir, '..', '..', 'static')
        
        os.makedirs(self.template_dir, exist_ok=True)
        os.makedirs(self.static_dir, exist_ok=True)
        os.makedirs(os.path.join(self.static_dir, 'js'), exist_ok=True)
        os.makedirs(os.path.join(self.static_dir, 'css'), exist_ok=True)
        
        # Créer les fichiers de template et statiques par défaut
        self._create_default_files()
        
        # Initialiser l'application Flask
        self.app = Flask(
            "AttackPathGraph", 
            template_folder=self.template_dir,
            static_folder=self.static_dir
        )

        @self.app.after_request
        def add_security_headers(response):
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' https://d3js.org https://cdn.jsdelivr.net; "
                "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
            )
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['Referrer-Policy'] = 'no-referrer'
            return response
        
        # Configurer les routes
        self._setup_routes()
        
        # Serveur en cours d'exécution
        self.server_running = False
    
    def _create_default_files(self):
        """
        Crée les fichiers de template et statiques par défaut.
        """
        # Template HTML principal
        index_template_path = os.path.join(self.template_dir, 'index.html')
        if not os.path.exists(index_template_path):
            with open(index_template_path, 'w', encoding='utf-8') as f:
                f.write("""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AttackPathGraph - Visualisation des chemins d'attaque</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/cytoscape@3.23.0/dist/cytoscape.min.js"></script>
</head>
<body>
    <header>
        <div class="container">
            <h1>AttackPathGraph</h1>
            <p>Visualisation des chemins d'attaque pour les tests d'intrusion</p>
        </div>
    </header>
    
    <main class="container">
        <div class="dashboard">
            <div class="sidebar">
                <div class="panel">
                    <h2>Statistiques</h2>
                    <div id="stats-container">
                        <div class="stat-item">
                            <span class="stat-label">Nœuds</span>
                            <span class="stat-value" id="node-count">0</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Relations</span>
                            <span class="stat-value" id="edge-count">0</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Chemins critiques</span>
                            <span class="stat-value" id="critical-path-count">0</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Score de risque max</span>
                            <span class="stat-value" id="max-risk-score">0.0</span>
                        </div>
                    </div>
                </div>
                
                <div class="panel">
                    <h2>Filtres</h2>
                    <div class="filter-group">
                        <label for="node-type-filter">Type de nœud</label>
                        <select id="node-type-filter" multiple>
                            <option value="host" selected>Hôtes</option>
                            <option value="service" selected>Services</option>
                            <option value="vulnerability" selected>Vulnérabilités</option>
                            <option value="user" selected>Utilisateurs</option>
                            <option value="exploit" selected>Exploits</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="risk-level-filter">Niveau de risque</label>
                        <select id="risk-level-filter" multiple>
                            <option value="Critical" selected>Critique</option>
                            <option value="High" selected>Élevé</option>
                            <option value="Medium" selected>Moyen</option>
                            <option value="Low" selected>Faible</option>
                            <option value="Info" selected>Info</option>
                        </select>
                    </div>
                    
                    <button id="apply-filters" class="btn">Appliquer les filtres</button>
                </div>
                
                <div class="panel">
                    <h2>Chemins d'attaque</h2>
                    <div id="attack-paths-list">
                        <!-- Les chemins d'attaque seront ajoutés ici dynamiquement -->
                    </div>
                </div>
            </div>
            
            <div class="main-content">
                <div class="panel">
                    <div class="panel-header">
                        <h2>Graphe d'attaque</h2>
                        <div class="panel-actions">
                            <button id="zoom-in" class="btn-icon" title="Zoom in">+</button>
                            <button id="zoom-out" class="btn-icon" title="Zoom out">-</button>
                            <button id="reset-view" class="btn-icon" title="Reset view">⟲</button>
                        </div>
                    </div>
                    <div id="graph-container"></div>
                </div>
                
                <div class="panel">
                    <h2>Détails</h2>
                    <div id="details-container">
                        <p class="empty-state">Sélectionnez un élément du graphe pour afficher ses détails.</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h2>MITRE ATT&CK</h2>
            <div id="mitre-container">
                <div class="mitre-tactics">
                    <!-- Les tactiques MITRE ATT&CK seront ajoutées ici dynamiquement -->
                </div>
                <div class="mitre-techniques">
                    <!-- Les techniques MITRE ATT&CK seront ajoutées ici dynamiquement -->
                </div>
            </div>
        </div>
        
        <div class="actions">
            <button id="export-neo4j" class="btn">Exporter vers Neo4j</button>
            <button id="generate-report" class="btn">Générer un rapport</button>
        </div>
    </main>
    
    <footer>
        <div class="container">
            <p>&copy; 2025 AttackPathGraph - Visualisation des chemins d'attaque pour les tests d'intrusion</p>
        </div>
    </footer>
    
    <script src="{{ url_for('static', filename='js/graph.js') }}"></script>
    <script src="{{ url_for('static', filename='js/app.js') }}"></script>
</body>
</html>""")
        
        # CSS
        css_path = os.path.join(self.static_dir, 'css', 'styles.css')
        if not _file_contains(css_path, '/* AttackPathGraph styles v2 */'):
            with open(css_path, 'w', encoding='utf-8') as f:
                f.write("""/* AttackPathGraph styles v2 */
/* Variables */
:root {
    --primary-color: #2c3e50;
    --secondary-color: #3498db;
    --accent-color: #e74c3c;
    --background-color: #f8f9fa;
    --panel-background: #ffffff;
    --text-color: #333333;
    --text-light: #666666;
    --border-color: #e0e0e0;
    --success-color: #2ecc71;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
    --info-color: #3498db;
    --shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

/* Reset et base */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: var(--background-color);
}

.container {
    width: 100%;
    max-width: 1400px;
    margin: 0 auto;
    padding: 0 20px;
}

/* En-tête */
header {
    background-color: var(--primary-color);
    color: white;
    padding: 20px 0;
    box-shadow: var(--shadow);
}

header h1 {
    font-size: 2.2rem;
    margin-bottom: 5px;
}

header p {
    font-size: 1.1rem;
    opacity: 0.8;
}

/* Mise en page principale */
main {
    padding: 30px 0;
}

.dashboard {
    display: flex;
    gap: 20px;
    margin-bottom: 30px;
}

.sidebar {
    width: 300px;
    flex-shrink: 0;
}

.main-content {
    flex-grow: 1;
}

/* Panneaux */
.panel {
    background-color: var(--panel-background);
    border-radius: 8px;
    box-shadow: var(--shadow);
    margin-bottom: 20px;
    overflow: hidden;
}

.panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 15px 20px;
    border-bottom: 1px solid var(--border-color);
}

.panel h2 {
    font-size: 1.3rem;
    color: var(--primary-color);
    padding: 15px 20px;
    border-bottom: 1px solid var(--border-color);
}

.panel-actions {
    display: flex;
    gap: 5px;
}

/* Statistiques */
#stats-container {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
    padding: 15px 20px;
}

.stat-item {
    display: flex;
    flex-direction: column;
}

.stat-label {
    font-size: 0.9rem;
    color: var(--text-light);
}

.stat-value {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--primary-color);
}

/* Filtres */
.filter-group {
    padding: 10px 20px;
}

.filter-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: 500;
}

.filter-group select {
    width: 100%;
    padding: 8px 10px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background-color: white;
}

/* Boutons */
.btn {
    display: inline-block;
    padding: 8px 16px;
    background-color: var(--secondary-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: 500;
    transition: background-color 0.2s;
}

.btn:hover {
    background-color: #2980b9;
}

.btn-icon {
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: var(--panel-background);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
    transition: all 0.2s;
}

.btn-icon:hover {
    background-color: var(--secondary-color);
    color: white;
    border-color: var(--secondary-color);
}

/* Liste des chemins d'attaque */
#attack-paths-list {
    padding: 10px 20px;
    max-height: 300px;
    overflow-y: auto;
}

.attack-path-item {
    padding: 10px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    margin-bottom: 10px;
    cursor: pointer;
    transition: all 0.2s;
}

.attack-path-item:hover {
    border-color: var(--secondary-color);
    background-color: rgba(52, 152, 219, 0.05);
}

.attack-path-item.active {
    border-color: var(--secondary-color);
    background-color: rgba(52, 152, 219, 0.1);
}

.attack-path-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 5px;
}

.attack-path-title {
    font-weight: 600;
}

.attack-path-score {
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 0.85rem;
}

.score-critical {
    background-color: rgba(231, 76, 60, 0.2);
    color: #c0392b;
}

.score-high {
    background-color: rgba(230, 126, 34, 0.2);
    color: #d35400;
}

.score-medium {
    background-color: rgba(241, 196, 15, 0.2);
    color: #f39c12;
}

.score-low {
    background-color: rgba(52, 152, 219, 0.2);
    color: #2980b9;
}

.score-info {
    background-color: rgba(46, 204, 113, 0.2);
    color: #27ae60;
}

/* Conteneur du graphe */
#graph-container {
    position: relative;
    height: 500px;
    background-color: #f5f5f5;
    border-radius: 0 0 8px 8px;
}

/* Détails */
#details-container {
    padding: 15px 20px;
    min-height: 200px;
}

.empty-state {
    color: var(--text-light);
    font-style: italic;
    text-align: center;
    padding: 20px;
}

.node-details h3 {
    margin-bottom: 10px;
    color: var(--primary-color);
}

.detail-item {
    margin-bottom: 8px;
}

.detail-label {
    font-weight: 600;
    display: inline-block;
    min-width: 120px;
}

/* MITRE ATT&CK */
#mitre-container {
    padding: 15px 20px;
}

.mitre-tactics {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 20px;
}

.mitre-tactic {
    padding: 8px 12px;
    background-color: rgba(52, 152, 219, 0.1);
    border: 1px solid rgba(52, 152, 219, 0.3);
    border-radius: 4px;
    font-weight: 500;
}

.mitre-techniques {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 15px;
}

.mitre-technique {
    padding: 12px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
}

.mitre-technique-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 8px;
}

.mitre-technique-id {
    font-weight: 600;
    color: var(--secondary-color);
}

.mitre-technique-name {
    font-weight: 600;
    margin-bottom: 5px;
}

.mitre-technique-tactic {
    font-size: 0.85rem;
    color: var(--text-light);
}

/* Actions */
.actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 20px;
}

/* Pied de page */
footer {
    background-color: var(--primary-color);
    color: white;
    padding: 20px 0;
    margin-top: 40px;
}

footer p {
    opacity: 0.8;
    text-align: center;
}

/* Responsive */
@media (max-width: 1024px) {
    .dashboard {
        flex-direction: column;
    }
    
    .sidebar {
        width: 100%;
    }
}

@media (max-width: 768px) {
    .mitre-techniques {
        grid-template-columns: 1fr;
    }
    
    #stats-container {
        grid-template-columns: 1fr;
    }
}""")
        
        # JavaScript pour le graphe
        graph_js_path = os.path.join(self.static_dir, 'js', 'graph.js')
        if not _file_contains(graph_js_path, '// AttackPathGraph graph.js v4'):
            with open(graph_js_path, 'w', encoding='utf-8') as f:
                f.write("""// AttackPathGraph graph.js v4
// Echappe les donnees importees avant insertion dans le DOM.
function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    })[character]);
}

// Classe pour gérer le graphe d'attaque
class AttackGraph {
    constructor(containerId) {
        this.containerId = containerId;
        this.cy = null;
        this.data = null;
        this.selectedNode = null;
        this.highlightedPath = null;
        this.filters = {
            nodeTypes: ['host', 'service', 'vulnerability', 'user', 'exploit'],
            riskLevels: ['Critical', 'High', 'Medium', 'Low', 'Info']
        };
        
        // Styles pour les différents types de nœuds
        this.nodeStyles = {
            host: {
                shape: 'rectangle',
                backgroundColor: '#3498db',
                borderColor: '#2980b9',
                borderWidth: 2
            },
            service: {
                shape: 'diamond',
                backgroundColor: '#2ecc71',
                borderColor: '#27ae60',
                borderWidth: 2
            },
            vulnerability: {
                shape: 'ellipse',
                backgroundColor: '#e74c3c',
                borderColor: '#c0392b',
                borderWidth: 2
            },
            user: {
                shape: 'hexagon',
                backgroundColor: '#9b59b6',
                borderColor: '#8e44ad',
                borderWidth: 2
            },
            exploit: {
                shape: 'triangle',
                backgroundColor: '#f39c12',
                borderColor: '#d35400',
                borderWidth: 2
            }
        };
    }
    
    // Initialiser le graphe
    init() {
        this.cy = cytoscape({
            container: document.getElementById(this.containerId),
            style: [
                {
                    selector: 'node',
                    style: {
                        'label': 'data(label)',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'text-wrap': 'wrap',
                        'text-max-width': '80px',
                        'font-size': '10px',
                        'color': '#fff',
                        'text-outline-width': 1,
                        'text-outline-color': '#000',
                        'background-color': '#666',
                        'border-width': 2,
                        'border-color': '#333'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'line-color': '#ccc',
                        'target-arrow-color': '#ccc',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(label)',
                        'font-size': '8px',
                        'text-rotation': 'autorotate',
                        'text-margin-y': -10,
                        'text-background-color': 'white',
                        'text-background-opacity': 0.7,
                        'text-background-padding': 2
                    }
                },
                {
                    selector: 'node[type = "host"]',
                    style: {
                        'shape': 'rectangle',
                        'background-color': '#3498db',
                        'border-color': '#2980b9'
                    }
                },
                {
                    selector: 'node[type = "service"]',
                    style: {
                        'shape': 'diamond',
                        'background-color': '#2ecc71',
                        'border-color': '#27ae60'
                    }
                },
                {
                    selector: 'node[type = "vulnerability"]',
                    style: {
                        'shape': 'ellipse',
                        'background-color': '#e74c3c',
                        'border-color': '#c0392b'
                    }
                },
                {
                    selector: 'node[type = "user"]',
                    style: {
                        'shape': 'hexagon',
                        'background-color': '#9b59b6',
                        'border-color': '#8e44ad'
                    }
                },
                {
                    selector: 'node[type = "exploit"]',
                    style: {
                        'shape': 'triangle',
                        'background-color': '#f39c12',
                        'border-color': '#d35400'
                    }
                },
                {
                    selector: 'node.highlight',
                    style: {
                        'border-width': 3,
                        'border-color': '#ffd700',
                        'border-opacity': 1,
                        'background-color': function(ele) {
                            return ele.style('background-color');
                        },
                        'text-outline-color': '#ffd700',
                        'z-index': 999
                    }
                },
                {
                    selector: 'edge.highlight',
                    style: {
                        'width': 3,
                        'line-color': '#ffd700',
                        'target-arrow-color': '#ffd700',
                        'z-index': 999
                    }
                },
                {
                    selector: 'node.selected',
                    style: {
                        'border-width': 4,
                        'border-color': '#ff0000',
                        'border-opacity': 1,
                        'background-color': function(ele) {
                            return ele.style('background-color');
                        },
                        'text-outline-color': '#ff0000',
                        'z-index': 9999
                    }
                }
            ],
            layout: {
                name: 'cose',
                idealEdgeLength: 100,
                nodeOverlap: 20,
                refresh: 20,
                fit: true,
                padding: 30,
                randomize: true,
                componentSpacing: 100,
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            }
        });
        
        // Événements
        this.cy.on('tap', 'node', (event) => {
            const node = event.target;
            this.selectNode(node);
        });
        
        this.cy.on('tap', (event) => {
            if (event.target === this.cy) {
                this.clearSelection();
            }
        });
        
        // Configurer les boutons de zoom
        document.getElementById('zoom-in').addEventListener('click', () => {
            this.cy.zoom(this.cy.zoom() * 1.2);
            this.cy.center();
        });
        
        document.getElementById('zoom-out').addEventListener('click', () => {
            this.cy.zoom(this.cy.zoom() / 1.2);
            this.cy.center();
        });
        
        document.getElementById('reset-view').addEventListener('click', () => {
            this.cy.fit();
        });
        
        // Configurer les filtres
        document.getElementById('apply-filters').addEventListener('click', () => {
            this.applyFilters();
        });
    }
    
    // Charger les données du graphe
    loadData(data) {
        this.data = data;
        
        // Convertir les données au format Cytoscape
        const elements = {
            nodes: [],
            edges: []
        };
        
        // Ajouter les nœuds
        for (const [id, attrs] of Object.entries(data.nodes)) {
            elements.nodes.push({
                data: {
                    id: id,
                    label: this.formatNodeLabel(id, attrs),
                    type: attrs.type || 'unknown',
                    ...attrs
                }
            });
        }
        
        // Ajouter les arêtes
        for (const edge of data.edges) {
            elements.edges.push({
                data: {
                    id: `${edge.source}-${edge.target}`,
                    source: edge.source,
                    target: edge.target,
                    label: edge.label || ''
                }
            });
        }
        
        this.cy.elements().remove();
        this.cy.add(elements);
        
        // Appliquer la disposition
        const layout = this.cy.layout({
            name: 'cose',
            idealEdgeLength: 100,
            nodeOverlap: 20,
            refresh: 20,
            fit: true,
            padding: 30,
            randomize: false,
            componentSpacing: 100,
            nodeRepulsion: 400000,
            edgeElasticity: 100,
            nestingFactor: 5,
            gravity: 80,
            numIter: 1000,
            initialTemp: 200,
            coolingFactor: 0.95,
            minTemp: 1.0
        });
        layout.run();
        
        // Mettre à jour les statistiques
        this.updateStats();
    }
    
    // Formater l'étiquette d'un nœud
    formatNodeLabel(id, attrs) {
        const type = attrs.type || 'unknown';
        
        switch (type) {
            case 'host':
                return attrs.hostname || id;
            case 'service':
                return attrs.service || id;
            case 'vulnerability':
                return attrs.name || id;
            case 'user':
                return attrs.username || id;
            case 'exploit':
                return attrs.name || id;
            default:
                return id;
        }
    }
    
    // Mettre à jour les statistiques
    updateStats() {
        if (!this.data) return;
        
        document.getElementById('node-count').textContent = Object.keys(this.data.nodes).length;
        document.getElementById('edge-count').textContent = this.data.edges.length;
        
        const attackPaths = this.data.attack_paths || [];
        document.getElementById('critical-path-count').textContent = attackPaths.length;
        const maxRiskScore = Math.max(0, ...attackPaths.map(path => Number(path.score) || 0));
        document.getElementById('max-risk-score').textContent = maxRiskScore.toFixed(1);
    }
    
    // Sélectionner un nœud
    selectNode(node) {
        // Désélectionner le nœud précédent
        if (this.selectedNode) {
            this.selectedNode.removeClass('selected');
        }
        
        // Sélectionner le nouveau nœud
        node.addClass('selected');
        this.selectedNode = node;
        
        // Afficher les détails du nœud
        this.showNodeDetails(node);
    }
    
    // Effacer la sélection
    clearSelection() {
        if (this.selectedNode) {
            this.selectedNode.removeClass('selected');
            this.selectedNode = null;
        }
        
        // Effacer les détails
        document.getElementById('details-container').innerHTML = '<p class="empty-state">Sélectionnez un élément du graphe pour afficher ses détails.</p>';
    }
    
    // Afficher les détails d'un nœud
    showNodeDetails(node) {
        const data = node.data();
        const detailsContainer = document.getElementById('details-container');
        
        let html = `<div class="node-details">`;
        html += `<h3>${escapeHtml(data.label)}</h3>`;
        
        html += `<div class="detail-item"><span class="detail-label">Type:</span> ${escapeHtml(data.type || 'Inconnu')}</div>`;
        
        // Détails spécifiques selon le type
        switch (data.type) {
            case 'host':
                html += `<div class="detail-item"><span class="detail-label">IP:</span> ${escapeHtml(data.ip || 'Inconnue')}</div>`;
                html += `<div class="detail-item"><span class="detail-label">OS:</span> ${escapeHtml(data.os || 'Inconnu')}</div>`;
                break;
            case 'service':
                html += `<div class="detail-item"><span class="detail-label">Service:</span> ${escapeHtml(data.service || 'Inconnu')}</div>`;
                html += `<div class="detail-item"><span class="detail-label">Port:</span> ${escapeHtml(data.port || 'Inconnu')}</div>`;
                break;
            case 'vulnerability':
                html += `<div class="detail-item"><span class="detail-label">Sévérité:</span> ${escapeHtml(data.severity || '0.0')}</div>`;
                html += `<div class="detail-item"><span class="detail-label">Description:</span> ${escapeHtml(data.description || 'Aucune description')}</div>`;
                break;
            case 'user':
                html += `<div class="detail-item"><span class="detail-label">Privilèges:</span> ${data.admin ? 'Administrateur' : 'Standard'}</div>`;
                break;
            case 'exploit':
                html += `<div class="detail-item"><span class="detail-label">Rank:</span> ${escapeHtml(data.rank || 'Normal')}</div>`;
                html += `<div class="detail-item"><span class="detail-label">Description:</span> ${escapeHtml(data.description || 'Aucune description')}</div>`;
                break;
        }
        
        // Connexions
        const incomingEdges = node.incomers('edge');
        const outgoingEdges = node.outgoers('edge');
        
        if (incomingEdges.length > 0) {
            html += `<h4>Connexions entrantes</h4>`;
            html += `<ul>`;
            incomingEdges.forEach(edge => {
                const source = this.cy.getElementById(edge.data('source'));
                html += `<li>${escapeHtml(source.data('label'))} <strong>${escapeHtml(edge.data('label') || 'lié à')}</strong> ${escapeHtml(data.label)}</li>`;
            });
            html += `</ul>`;
        }
        
        if (outgoingEdges.length > 0) {
            html += `<h4>Connexions sortantes</h4>`;
            html += `<ul>`;
            outgoingEdges.forEach(edge => {
                const target = this.cy.getElementById(edge.data('target'));
                html += `<li>${escapeHtml(data.label)} <strong>${escapeHtml(edge.data('label') || 'lié à')}</strong> ${escapeHtml(target.data('label'))}</li>`;
            });
            html += `</ul>`;
        }
        
        html += `</div>`;
        detailsContainer.innerHTML = html;
    }
    
    // Mettre en évidence un chemin d'attaque
    highlightPath(path) {
        // Réinitialiser le chemin précédent
        this.clearHighlightedPath();
        
        if (!path || path.length === 0) return;
        
        // Mettre en évidence les nœuds du chemin
        for (const nodeId of path) {
            const node = this.cy.getElementById(nodeId);
            if (node.length > 0) {
                node.addClass('highlight');
            }
        }
        
        // Mettre en évidence les arêtes du chemin
        for (let i = 0; i < path.length - 1; i++) {
            const sourceId = path[i];
            const targetId = path[i + 1];
            const edge = this.cy.edges().filter(candidate =>
                candidate.data('source') === sourceId && candidate.data('target') === targetId
            );
            if (edge.length > 0) {
                edge.addClass('highlight');
            }
        }
        
        this.highlightedPath = path;
        
        // Centrer la vue sur le chemin
        const nodesToFit = path.map(id => this.cy.getElementById(id));
        this.cy.fit(this.cy.collection(nodesToFit), 50);
    }
    
    // Effacer le chemin mis en évidence
    clearHighlightedPath() {
        if (this.highlightedPath) {
            this.cy.elements('.highlight').removeClass('highlight');
            this.highlightedPath = null;
        }
    }
    
    // Appliquer les filtres
    applyFilters() {
        // Récupérer les types de nœuds sélectionnés
        const nodeTypeSelect = document.getElementById('node-type-filter');
        const selectedNodeTypes = Array.from(nodeTypeSelect.selectedOptions).map(option => option.value);
        
        // Récupérer les niveaux de risque sélectionnés
        const riskLevelSelect = document.getElementById('risk-level-filter');
        const selectedRiskLevels = Array.from(riskLevelSelect.selectedOptions).map(option => option.value);
        
        // Mettre à jour les filtres
        this.filters.nodeTypes = selectedNodeTypes;
        this.filters.riskLevels = selectedRiskLevels;
        
        // Appliquer les filtres
        this.cy.nodes().forEach(node => {
            const nodeType = node.data('type');
            const riskLevel = node.data('risk_level');
            
            const typeMatch = selectedNodeTypes.includes(nodeType);
            const riskMatch = !riskLevel || selectedRiskLevels.includes(riskLevel);
            
            if (typeMatch && riskMatch) {
                node.style('display', 'element');
            } else {
                node.style('display', 'none');
            }
        });
    }
}""")
        
        # JavaScript pour l'application
        app_js_path = os.path.join(self.static_dir, 'js', 'app.js')
        if not _file_contains(app_js_path, '// AttackPathGraph app.js v3'):
            with open(app_js_path, 'w', encoding='utf-8') as f:
                f.write("""// AttackPathGraph app.js v3
// Initialisation de l'application
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser le graphe
    const graph = new AttackGraph('graph-container');
    graph.init();
    
    // Charger les données du graphe
    fetch('/api/graph')
        .then(response => response.json())
        .then(data => {
            graph.loadData(data);
            loadAttackPaths(data.attack_paths, graph);
            loadMitreData(data.mitre);
        })
        .catch(error => {
            console.error('Erreur lors du chargement des données:', error);
            document.getElementById('graph-container').innerHTML = `
                <div class="empty-state">
                    <p>Erreur lors du chargement des données du graphe.</p>
                    <p>Veuillez réessayer ou vérifier les logs du serveur.</p>
                </div>
            `;
        });
    
    // Configurer les boutons d'action
    document.getElementById('export-neo4j').addEventListener('click', function() {
        fetch('/api/export/neo4j', {
            method: 'POST',
            headers: { 'X-Requested-With': 'AttackPathGraph' }
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Graphe exporté avec succès vers Neo4j!');
                } else {
                    alert("Erreur lors de l'export: " + data.error);
                }
            })
            .catch(error => {
                console.error("Erreur lors de l'export:", error);
                alert("Erreur lors de l'export vers Neo4j.");
            });
    });
    
    document.getElementById('generate-report').addEventListener('click', function() {
        fetch('/generate-report', {
            method: 'POST',
            headers: { 'X-Requested-With': 'AttackPathGraph' }
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                return response.blob();
            })
            .then(blob => {
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = 'attack-path-report.html';
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
            })
            .catch(error => {
                console.error('Erreur lors de la génération du rapport:', error);
                alert('Erreur lors de la génération du rapport.');
            });
    });
});

// Charger les chemins d'attaque
function loadAttackPaths(paths, graph) {
    if (!paths || paths.length === 0) {
        document.getElementById('attack-paths-list').innerHTML = `<p class="empty-state">Aucun chemin d'attaque trouvé.</p>`;
        return;
    }
    
    const container = document.getElementById('attack-paths-list');
    container.innerHTML = '';
    
    paths.forEach((path, index) => {
        const scoreClass = getScoreClass(path.score);
        
        const pathItem = document.createElement('div');
        pathItem.className = 'attack-path-item';
        pathItem.innerHTML = `
            <div class="attack-path-header">
                <span class="attack-path-title">Chemin #${index + 1}</span>
                <span class="attack-path-score ${scoreClass}">${path.score.toFixed(1)}</span>
            </div>
            <div class="attack-path-info">
                <small>${path.path.length} nœuds | ${escapeHtml(path.risk_level)}</small>
            </div>
        `;
        
        pathItem.addEventListener('click', function() {
            // Désélectionner tous les chemins
            document.querySelectorAll('.attack-path-item').forEach(item => {
                item.classList.remove('active');
            });
            
            // Sélectionner ce chemin
            pathItem.classList.add('active');
            
            // Mettre en évidence le chemin dans le graphe
            graph.highlightPath(path.path);
        });
        
        container.appendChild(pathItem);
    });
}

// Charger les données MITRE ATT&CK
function loadMitreData(mitreData) {
    if (!mitreData) return;
    
    // Afficher les tactiques
    const tacticsContainer = document.querySelector('.mitre-tactics');
    tacticsContainer.innerHTML = '';
    
    if (mitreData.tactics && mitreData.tactics.length > 0) {
        mitreData.tactics.forEach(tactic => {
            const tacticElement = document.createElement('div');
            tacticElement.className = 'mitre-tactic';
            tacticElement.textContent = tactic;
            tacticsContainer.appendChild(tacticElement);
        });
    } else {
        tacticsContainer.innerHTML = '<p class="empty-state">Aucune tactique MITRE ATT&CK identifiée.</p>';
    }
    
    // Afficher les techniques
    const techniquesContainer = document.querySelector('.mitre-techniques');
    techniquesContainer.innerHTML = '';
    
    if (mitreData.techniques && mitreData.techniques.length > 0) {
        mitreData.techniques.forEach(technique => {
            const techniqueElement = document.createElement('div');
            techniqueElement.className = 'mitre-technique';
            techniqueElement.innerHTML = `
                <div class="mitre-technique-header">
                    <span class="mitre-technique-id">${escapeHtml(technique.technique_id)}</span>
                    <span class="mitre-technique-tactic">${escapeHtml(technique.tactic)}</span>
                </div>
                <div class="mitre-technique-name">${escapeHtml(technique.name)}</div>
            `;
            techniquesContainer.appendChild(techniqueElement);
        });
    } else {
        techniquesContainer.innerHTML = '<p class="empty-state">Aucune technique MITRE ATT&CK identifiée.</p>';
    }
}

// Obtenir la classe CSS pour un score
function getScoreClass(score) {
    if (score >= 9.0) return 'score-critical';
    if (score >= 7.0) return 'score-high';
    if (score >= 4.0) return 'score-medium';
    if (score >= 2.0) return 'score-low';
    return 'score-info';
}""")
    
    def _setup_routes(self):
        """
        Configure les routes de l'application Flask.
        """
        @self.app.route('/')
        def index():
            return render_template('index.html')

        @self.app.route('/healthz')
        def healthz():
            return jsonify({'status': 'ok'})
        
        @self.app.route('/api/graph')
        def get_graph():
            if self.graph is None:
                return jsonify({'error': 'Aucun graphe disponible'}), 404
            
            # Convertir le graphe NetworkX en format JSON
            nodes = {}
            for node, attrs in self.graph.nodes(data=True):
                nodes[node] = attrs
            
            edges = []
            for src, dst, attrs in self.graph.edges(data=True):
                edges.append({
                    'source': src,
                    'target': dst,
                    'label': attrs.get('label', '')
                })
            
            # Ajouter les chemins d'attaque critiques si disponibles
            attack_paths = []
            if self.analyzer:
                critical_paths = self.analyzer.get_critical_attack_paths()
                for path_data in critical_paths:
                    attack_paths.append({
                        'path': path_data['path'],
                        'score': path_data['score'],
                        'length': path_data['length'],
                        'risk_level': self.scorer.get_risk_level(path_data['score']) if self.scorer else 'Unknown'
                    })
            
            # Ajouter les données MITRE ATT&CK si disponibles
            mitre_data = None
            if self.mitre_integration and attack_paths:
                # Prendre le chemin le plus critique
                critical_path = attack_paths[0]['path'] if attack_paths else []
                
                # Extraire les nœuds du chemin
                path_nodes = []
                for node_id in critical_path:
                    if node_id in nodes:
                        path_nodes.append({**nodes[node_id], 'id': node_id})
                
                # Mapper le chemin aux techniques MITRE ATT&CK
                mitre_data = self.mitre_integration.map_attack_path_to_techniques(path_nodes)
            
            return jsonify({
                'nodes': nodes,
                'edges': edges,
                'attack_paths': attack_paths,
                'mitre': mitre_data
            })
        
        @self.app.route('/api/export/neo4j', methods=['POST'])
        def export_to_neo4j():
            if request.headers.get('X-Requested-With') != 'AttackPathGraph':
                return jsonify({'success': False, 'error': 'Requête refusée'}), 403

            export_enabled = os.environ.get('ATTACKPATHGRAPH_ENABLE_NEO4J_EXPORT', '').lower()
            if export_enabled not in {'1', 'true', 'yes'}:
                return jsonify({
                    'success': False,
                    'error': 'Export Neo4j désactivé par configuration'
                }), 403

            if self.graph is None:
                return jsonify({'success': False, 'error': 'Aucun graphe disponible'}), 404
            
            try:
                from core.graph_engine import AttackGraph
                attack_graph = AttackGraph()
                attack_graph.graph = self.graph
                attack_graph.export_to_neo4j(clear=False)
                return jsonify({'success': True})
            except Exception as e:
                logger.error(f"Erreur lors de l'export vers Neo4j: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/generate-report', methods=['POST'])
        def generate_report():
            if request.headers.get('X-Requested-With') != 'AttackPathGraph':
                return "Requête refusée", 403

            if self.graph is None:
                return "Aucun graphe disponible", 404
            
            try:
                from core.reporting.report_generator import ReportGenerator
                
                # Générer le rapport HTML
                report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'reports')
                os.makedirs(report_dir, exist_ok=True)
                
                report_path = os.path.join(report_dir, f"attack_path_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
                
                generator = ReportGenerator(self.graph, self.analyzer)
                generator.generate_html_report(report_path)
                
                # Servir le fichier
                return send_from_directory(
                    os.path.dirname(report_path),
                    os.path.basename(report_path),
                    as_attachment=True,
                    download_name='attack-path-report.html'
                )
            except Exception as e:
                logger.error(f"Erreur lors de la génération du rapport: {e}")
                return f"Erreur lors de la génération du rapport: {e}", 500
        
        @self.app.route('/static/<path:path>')
        def serve_static(path):
            return send_from_directory(self.static_dir, path)
    
    def start(self, host='0.0.0.0', port=5000, debug=False, open_browser=True):
        """
        Démarre le serveur web.
        
        Args:
            host (str, optional): Hôte d'écoute. Par défaut '0.0.0.0'.
            port (int, optional): Port d'écoute. Par défaut 5000.
            debug (bool, optional): Mode debug. Par défaut False.
            open_browser (bool, optional): Ouvrir le navigateur. Par défaut True.
        """
        if self.server_running:
            logger.warning("Le serveur est déjà en cours d'exécution")
            return
        
        # Ouvrir le navigateur
        if open_browser:
            threading.Timer(1.5, lambda: webbrowser.open(f"http://localhost:{port}")).start()
        
        # Démarrer le serveur
        logger.info(f"Démarrage du serveur web sur http://{host}:{port}")
        self.server_running = True
        if debug:
            self.app.run(host=host, port=port, debug=debug)
        else:
            from waitress import serve

            serve(self.app, host=host, port=port)
    
    def stop(self):
        """
        Arrête le serveur web.
        """
        if not self.server_running:
            logger.warning("Le serveur n'est pas en cours d'exécution")
            return
        
        # Arrêter le serveur
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Pas dans un environnement Werkzeug')
        func()
        
        logger.info("Serveur web arrêté")
        self.server_running = False
