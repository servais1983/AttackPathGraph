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

    def export_to_neo4j(self, uri="bolt://localhost:7687", user="neo4j", password="neo4j"):
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