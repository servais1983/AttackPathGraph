#!/bin/bash
echo "[*] Installation d'AttackPathGraph (Pentest Graph) sur Kali..."

sudo apt update
sudo apt install -y python3 python3-pip
pip3 install -r requirements.txt

echo "[+] Installation terminée. Utilisez : python3 pentest_graph.py --ascii --nmap demo/nmap_sample.xml --bh demo/bloodhound_sample.json"