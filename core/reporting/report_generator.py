#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de génération de rapports HTML/PDF pour AttackPathGraph.
Ce module permet de générer des rapports détaillés sur les chemins d'attaque.
"""

import os
import logging
import datetime
import jinja2

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Classe pour la génération de rapports détaillés sur les chemins d'attaque.
    """
    
    def __init__(self, graph, analyzer=None):
        """
        Initialise le générateur de rapports.
        
        Args:
            graph (nx.DiGraph): Graphe d'attaque NetworkX
            analyzer (AttackPathAnalyzer, optional): Analyseur de chemins d'attaque
        """
        self.graph = graph
        self.analyzer = analyzer
        self.template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'templates')
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Créer le répertoire templates s'il n'existe pas
        os.makedirs(self.template_dir, exist_ok=True)
        
        # Créer un template par défaut s'il n'existe pas
        self._create_default_templates()
    
    def _create_default_templates(self):
        """
        Crée les templates par défaut s'ils n'existent pas.
        """
        # Template HTML principal
        main_template_path = os.path.join(self.template_dir, 'report.html')
        if not os.path.exists(main_template_path):
            with open(main_template_path, 'w', encoding='utf-8') as f:
                f.write("""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .critical {
            color: #e74c3c;
            font-weight: bold;
        }
        .high {
            color: #e67e22;
            font-weight: bold;
        }
        .medium {
            color: #f1c40f;
            font-weight: bold;
        }
        .low {
            color: #3498db;
        }
        .info {
            color: #2ecc71;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .path-container {
            margin-bottom: 30px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .path-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .path-score {
            font-size: 1.2em;
            padding: 5px 10px;
            border-radius: 3px;
            background-color: #f8f9fa;
        }
        .node-list {
            list-style-type: none;
            padding-left: 0;
        }
        .node-item {
            padding: 10px;
            margin-bottom: 5px;
            border-left: 3px solid #3498db;
            background-color: #f8f9fa;
        }
        .edge-arrow {
            text-align: center;
            font-size: 1.5em;
            color: #7f8c8d;
            margin: 5px 0;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>Rapport généré le {{ date }}</p>
    </div>
    
    <div class="summary">
        <h2>Résumé</h2>
        <p>Ce rapport présente l'analyse des chemins d'attaque potentiels identifiés dans le réseau.</p>
        <ul>
            <li><strong>Nombre total de chemins d'attaque :</strong> {{ summary.total_paths }}</li>
            <li><strong>Chemins critiques identifiés :</strong> {{ summary.critical_paths }}</li>
            <li><strong>Points d'entrée :</strong> {{ summary.entry_points|length }}</li>
            <li><strong>Actifs critiques :</strong> {{ summary.critical_assets|length }}</li>
        </ul>
    </div>
    
    <h2>Chemins d'attaque critiques</h2>
    
    {% for path_data in summary.paths %}
    <div class="path-container">
        <div class="path-header">
            <h3>Chemin d'attaque #{{ loop.index }}</h3>
            <div class="path-score {% if path_data.score > 8 %}critical{% elif path_data.score > 6 %}high{% elif path_data.score > 4 %}medium{% elif path_data.score > 2 %}low{% else %}info{% endif %}">
                Score: {{ "%.2f"|format(path_data.score) }}
            </div>
        </div>
        
        <p><strong>Longueur du chemin :</strong> {{ path_data.length }} nœuds</p>
        
        <h4>Séquence d'attaque</h4>
        <ul class="node-list">
            {% for node in path_data.details.nodes %}
            <li class="node-item">
                <strong>{{ node.id }}</strong> ({{ node.type }})
                {% if node.type == 'vulnerability' %}
                <br>Sévérité: <span class="{% if node.severity > 8 %}critical{% elif node.severity > 6 %}high{% elif node.severity > 4 %}medium{% elif node.severity > 2 %}low{% else %}info{% endif %}">{{ "%.1f"|format(node.severity) }}</span>
                {% endif %}
                {% if node.type == 'service' %}
                <br>Service: {{ node.service }}
                {% endif %}
                {% if node.type == 'host' %}
                <br>OS: {{ node.os if node.os else 'Inconnu' }}
                {% endif %}
                {% if node.type == 'user' %}
                <br>Privilèges: {{ 'Administrateur' if node.admin else 'Standard' }}
                {% endif %}
            </li>
            {% if not loop.last %}
            <li class="edge-arrow">↓</li>
            {% endif %}
            {% endfor %}
        </ul>
        
        <h4>Détails des relations</h4>
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Relation</th>
                    <th>Cible</th>
                </tr>
            </thead>
            <tbody>
                {% for edge in path_data.details.edges %}
                <tr>
                    <td>{{ edge.source }}</td>
                    <td>{{ edge.label }}</td>
                    <td>{{ edge.target }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endfor %}
    
    <h2>Points d'entrée identifiés</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Détails</th>
            </tr>
        </thead>
        <tbody>
            {% for entry_point in summary.entry_points %}
            <tr>
                <td>{{ entry_point }}</td>
                <td>{{ graph.nodes[entry_point].type }}</td>
                <td>
                    {% if graph.nodes[entry_point].type == 'service' %}
                    Service: {{ graph.nodes[entry_point].service }}
                    {% elif graph.nodes[entry_point].type == 'user' %}
                    Utilisateur {{ 'externe' if graph.nodes[entry_point].external else '' }}
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <h2>Actifs critiques identifiés</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Détails</th>
            </tr>
        </thead>
        <tbody>
            {% for asset in summary.critical_assets %}
            <tr>
                <td>{{ asset }}</td>
                <td>{{ graph.nodes[asset].type }}</td>
                <td>
                    {% if graph.nodes[asset].type == 'host' %}
                    OS: {{ graph.nodes[asset].os if graph.nodes[asset].os else 'Inconnu' }}
                    {% elif graph.nodes[asset].type == 'user' %}
                    Privilèges: {{ 'Administrateur' if graph.nodes[asset].admin else 'Standard' }}
                    {% elif graph.nodes[asset].type == 'service' %}
                    Service: {{ graph.nodes[asset].service }}
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <div class="footer">
        <p>Rapport généré par AttackPathGraph</p>
        <p>© {{ year }} - Tous droits réservés</p>
    </div>
</body>
</html>""")
    
    def generate_html_report(self, output_path, title="Rapport d'analyse des chemins d'attaque"):
        """
        Génère un rapport HTML détaillé.
        
        Args:
            output_path (str): Chemin de sortie pour le fichier HTML
            title (str, optional): Titre du rapport
            
        Returns:
            str: Chemin du fichier HTML généré
        """
        if self.analyzer is None:
            from core.analysis.path_analyzer import AttackPathAnalyzer
            self.analyzer = AttackPathAnalyzer(self.graph)
        
        # Obtenir le résumé des chemins d'attaque
        summary = self.analyzer.get_attack_path_summary()
        
        # Préparer les données pour le template
        template_data = {
            'title': title,
            'date': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            'year': datetime.datetime.now().year,
            'summary': summary,
            'graph': self.graph
        }
        
        # Charger et rendre le template
        template = self.env.get_template('report.html')
        html_content = template.render(**template_data)
        
        # Écrire le fichier HTML
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Rapport HTML généré: {output_path}")
        return output_path
    
    def generate_pdf_report(self, output_path, title="Rapport d'analyse des chemins d'attaque"):
        """
        Génère un rapport PDF détaillé.
        
        Args:
            output_path (str): Chemin de sortie pour le fichier PDF
            title (str, optional): Titre du rapport
            
        Returns:
            str: Chemin du fichier PDF généré
        """
        # Générer d'abord le HTML
        html_path = output_path.replace('.pdf', '.html')
        self.generate_html_report(html_path, title)
        
        # Convertir le HTML en PDF. WeasyPrint needs native libraries on some
        # systems, so import it only when PDF generation is requested.
        try:
            import weasyprint
        except OSError as exc:
            raise RuntimeError(
                "PDF generation requires WeasyPrint native dependencies. "
                "Install the OS packages documented by WeasyPrint or generate HTML instead."
            ) from exc

        html = weasyprint.HTML(filename=html_path)
        html.write_pdf(output_path)
        
        # Supprimer le fichier HTML temporaire
        os.remove(html_path)
        
        logger.info(f"Rapport PDF généré: {output_path}")
        return output_path
    
    def get_graph_statistics(self):
        """
        Calcule des statistiques sur le graphe d'attaque.
        
        Returns:
            dict: Statistiques du graphe
        """
        stats = {
            'nodes': {
                'total': self.graph.number_of_nodes(),
                'by_type': {}
            },
            'edges': {
                'total': self.graph.number_of_edges(),
                'by_label': {}
            }
        }
        
        # Statistiques des nœuds par type
        for _, attrs in self.graph.nodes(data=True):
            node_type = attrs.get('type', 'unknown')
            stats['nodes']['by_type'][node_type] = stats['nodes']['by_type'].get(node_type, 0) + 1
        
        # Statistiques des arêtes par label
        for _, _, attrs in self.graph.edges(data=True):
            edge_label = attrs.get('label', 'unknown')
            stats['edges']['by_label'][edge_label] = stats['edges']['by_label'].get(edge_label, 0) + 1
        
        return stats
