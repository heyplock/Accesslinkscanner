import warnings
warnings.filterwarnings("ignore")
import socket
import requests
import urllib3
import json
from pathlib import Path
import readchar
import os
import concurrent.futures
import re
from ipwhois import IPWhois

# === Couleurs ===
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

CONFIG_PATH = Path("config.json")
DEFAULT_CONFIG = {
    "ports": [80, 443],
    "timeout": 5
}

def load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    else:
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)

def is_port_open(ip, port, timeout_value):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_value)
        return sock.connect_ex((ip, port)) == 0

def check_protocol(ip, port, protocol, timeout_value):
    url = f"{protocol}://{ip}:{port}"
    try:
        response = requests.get(url, timeout=timeout_value, verify=False)
        return response.status_code < 400
    except requests.exceptions.RequestException:
        return False

def is_valid_ip_or_domain(target):
    # IPv4 stricte
    ip_regex = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ip_regex.match(target):
        # Vérification valeur (pas plus de 255 par octet)
        try:
            parts = [int(p) for p in target.split(".")]
            if all(0 <= part <= 255 for part in parts):
                return True
        except:
            return False
    # Domaines style domaine.tld
    domain_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    )
    if domain_regex.match(target):
        return True
    return False

def print_ip_whois(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=2)
        provider = res.get('network', {}).get('name', 'Inconnu')
        org = res.get('network', {}).get('org', 'Inconnu')

        all_mails = set()

        for contact in res.get('objects', {}).values():
            email = contact.get('contact', {}).get('email')
            if isinstance(email, list):
                for em in email:
                    if isinstance(em, str) and '@' in em:
                        all_mails.add(em)
                    elif isinstance(em, dict) and 'value' in em and '@' in em['value']:
                        all_mails.add(em['value'])
            elif isinstance(email, str) and '@' in email:
                all_mails.add(email)
            elif isinstance(email, dict) and 'value' in email and '@' in email['value']:
                all_mails.add(email['value'])

            remarks = contact.get('remarks', [])
            if remarks is None:
                remarks = []
            for remark in remarks:
                if isinstance(remark, dict):
                    descrs = remark.get('description', [])
                    if descrs is None:
                        descrs = []
                    for descr in descrs:
                        for part in descr.split():
                            if '@' in part:
                                all_mails.add(part)
                elif isinstance(remark, str):
                    for part in remark.split():
                        if '@' in part:
                            all_mails.add(part)

        # Trie pour mettre les emails d'abuse en priorité
        abuse_first = sorted(all_mails, key=lambda m: (not m.lower().startswith('abuse') and 'abuse' not in m.lower(), m))
        print(f"\n🌍 Fournisseur/Org : {org} | Réseau : {provider}")
        if abuse_first:
            print(f"📧 Adresse(s) abuse trouvée(s) : {', '.join(abuse_first)}")
        else:
            print(f"📧 Adresse abuse : Non trouvée")
    except Exception as e:
        print(f"{RED}❌ Impossible d'obtenir les infos Whois pour cette IP : {e}{RESET}")


def scan(ip, ports, timeout):
    print(f"\n🔎 Résultats pour {ip} (timeout : {timeout}s) :\n")
    results = []

    # Fonction unique pour thread : (proto, port)
    def scan_one(args):
        port, proto = args
        url = f"{proto}://{ip}:{port}"
        is_open = is_port_open(ip, port, timeout)
        if is_open and check_protocol(ip, port, proto, timeout):
            return (True, url)
        else:
            return (False, url)

    # On prépare toutes les combinaisons (port, proto)
    jobs = []
    for port in ports:
        for proto in ["http", "https"]:
            jobs.append((port, proto))

    # ThreadPool : scan parallèle
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        for result, url in executor.map(scan_one, jobs):
            if result:
                print(f"{GREEN}✅ {url}{RESET}")
            else:
                print(f"{RED}❌ {url}{RESET}")

    print("\n" + "-"*50 + "\n")

    # Whois uniquement si c'est une IPv4 publique ou privée
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        print_ip_whois(ip)

def manage_ports(config):
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n⚙️  Gestion des ports à scanner")
        print(f"Ports actuels : {config['ports']}")
        print("1. ➕ Ajouter un port")
        print("2. ➖ Retirer un port")
        print("3. 🔙 Retour\n")

        try:
            key = readchar.readkey()
        except UnicodeDecodeError:
            continue  # Clear screen and redisplay the menu

        if key == '1':
            port_input = input("➡️  Entrez un port à ajouter : ").strip()
            if port_input.isdigit():
                port = int(port_input)
                if port not in config['ports']:
                    config['ports'].append(port)
                    save_config(config)
                    print(f"✅ Port {port} ajouté.")
                else:
                    print("⚠️  Port déjà présent.")
            else:
                print("❌ Invalide.")
            input("Appuie sur Entrée pour continuer...")
        elif key == '2':
            port_input = input("➡️  Entrez un port à retirer : ").strip()
            if port_input.isdigit():
                port = int(port_input)
                if port in config['ports']:
                    config['ports'].remove(port)
                    save_config(config)
                    print(f"✅ Port {port} retiré.")
                else:
                    print("⚠️  Ce port n'existe pas.")
            else:
                print("❌ Invalide.")
            input("Appuie sur Entrée pour continuer...")
        elif key == '3' or key == readchar.key.ESC:
            os.system('cls' if os.name == 'nt' else 'clear')
            break
        # Si touche inconnue ou erreur, on clear et redisplay le menu sans message

def manage_timeout(config):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\n⏱️  Timeout actuel : {config['timeout']} seconde(s)")
    timeout_input = input("➡️  Entrez un nouveau timeout (en secondes) : ").strip()
    try:
        new_timeout = float(timeout_input)
        if new_timeout > 0:
            config['timeout'] = new_timeout
            save_config(config)
            print(f"✅ Timeout mis à jour : {new_timeout} seconde(s)")
        else:
            print("❌ Doit être > 0.")
    except ValueError:
        print("❌ Nombre invalide.")
    input("Appuie sur Entrée pour continuer...")
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    config = load_config()

    while True:
        # NE PAS clear l'écran ici, pour garder l'historique
        print("============================================")
        print("🛠️  Multitool - Scanner HTTP/HTTPS simplifié\n")
        print("👉 Entrez une adresse IP ou un nom de domaine")
        print("📌 Tape 'P' pour gérer les ports, 'T' pour le timeout\n")

        key = readchar.readkey()
        if key.lower() == 'p':
            manage_ports(config)
        elif key.lower() == 't':
            manage_timeout(config)
        elif key == readchar.key.CTRL_C:
            print("\nFermeture du programme.")
            break
        else:
            print(key, end="", flush=True)
            ip = key + input()
            target = ip.strip()
            if is_valid_ip_or_domain(target):
                scan(target, config['ports'], config['timeout'])
            else:
                print(f"{RED}❌ Adresse IP ou nom de domaine invalide : {target}{RESET}")

if __name__ == "__main__":
    main()
