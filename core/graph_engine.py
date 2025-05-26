import networkx as nx
from py2neo import Graph, Node, Relationship

class AttackGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_nodes_edges_from_nmap(self, data):
        for host, services in data.items():
            self.graph.add_node(host, type="host")
            for port, service in services:
                self.graph.add_node(f"{host}:{port}", type="service", service=service)
                self.graph.add_edge(host, f"{host}:{port}", label="exposes")

    def add_nodes_edges_from_bloodhound(self, data):
        for user, targets in data.items():
            self.graph.add_node(user, type="user")
            for tgt in targets:
                self.graph.add_edge(user, tgt, label="can_access")

    def display_ascii(self):
        print("[*] Graphe ASCII (simplifié) :")
        for src, dst, data in self.graph.edges(data=True):
            print(f"{src} --[{data.get('label', 'link')}]-> {dst}")

    def export_to_neo4j(self, uri=None, user=None, password=None):
        """
        Exporte le graphe vers Neo4j.
        
        Args:
            uri (str, optional): URI de connexion Neo4j. Si None, utilise la variable d'environnement NEO4J_URI ou la valeur par défaut.
            user (str, optional): Nom d'utilisateur Neo4j. Si None, utilise la variable d'environnement NEO4J_USER ou la valeur par défaut.
            password (str, optional): Mot de passe Neo4j. Si None, utilise la variable d'environnement NEO4J_PASSWORD ou la valeur par défaut.
        """
        import os
        
        # Utiliser les variables d'environnement ou les valeurs par défaut
        uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = user or os.environ.get("NEO4J_USER", "neo4j")
        password = password or os.environ.get("NEO4J_PASSWORD", "neo4j")
        
        print("[*] Export vers Neo4j...")
        neo = Graph(uri, auth=(user, password))
        neo.delete_all()

        for node, attrs in self.graph.nodes(data=True):
            neo.merge(Node(attrs.get("type", "Node"), name=node))

        for src, dst, data in self.graph.edges(data=True):
            a = Node(self.graph.nodes[src].get("type", "Node"), name=src)
            b = Node(self.graph.nodes[dst].get("type", "Node"), name=dst)
            rel = Relationship(a, data.get("label", "LINKS_TO"), b)
            neo.merge(rel)

        print("[+] Export terminé.")