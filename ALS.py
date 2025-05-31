import socket
import requests
import urllib3
import json
import re
from pathlib import Path
import readchar
import os
import concurrent.futures
from ipwhois import IPWhois
import warnings
from datetime import datetime

warnings.filterwarnings("ignore")

# === Couleurs ===
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
BLUE = "\033[94m"
YELLOW = "\033[93m"

SEP_WIDTH = 70

CONFIG_PATH = Path.home() / "Documents" / "AccessLinkScanner" / "config.json"
DEFAULT_CONFIG = {
    "ports": [80, 443],
    "timeout": 5,
    "logging": False,
    "whois": True
}

def print_separator(style="-"):
    print("\n" + style*SEP_WIDTH + "\n")

def print_banner():
    print_separator("=")
    print(f"{GREEN}🛠️  Multitool - Scanner HTTP/HTTPS stylisé{RESET}")
    print_separator("=")

def print_menu(first=False, config=None):
    if first:
        print(f"{YELLOW}👉 Entrez une adresse IP ou un nom de domaine")
        print(f"{RED}📌 Tape 'P' pour gérer les ports, 'T' pour le timeout, 'L' pour activer/désactiver les logs, 'W' pour activer/désactiver WHOIS{RESET}\n")
    else:
        line = f"{YELLOW}👉 Entrez une adresse IP ou un nom de domaine{RESET}"
        if config is not None:
            if config.get('logging'):
                line += f"   {GREEN}[LOG ACTIF]{RESET}"
            if config.get('whois', True):
                line += f"   {BLUE}[WHOIS ON]{RESET}"
            else:
                line += f"   {RED}[WHOIS OFF]{RESET}"
        print(line)

def load_config():
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    else:
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(config):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
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
    ip_regex = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ip_regex.match(target):
        try:
            parts = [int(p) for p in target.split(".")]
            if all(0 <= part <= 255 for part in parts):
                return True
        except:
            return False
    domain_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    )
    if domain_regex.match(target):
        return True
    return False

def write_log(content):
    log_path = CONFIG_PATH.parent / "scan.log"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(content + "\n")

def get_ip_whois_log(ip):
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
            remarks = contact.get('remarks', []) or []
            for remark in remarks:
                if isinstance(remark, dict):
                    descrs = remark.get('description', []) or []
                    for descr in descrs:
                        for part in descr.split():
                            if '@' in part:
                                all_mails.add(part)
                elif isinstance(remark, str):
                    for part in remark.split():
                        if '@' in part:
                            all_mails.add(part)
        abuse_first = sorted(all_mails, key=lambda m: (not m.lower().startswith('abuse') and 'abuse' not in m.lower(), m))
        log =  f"WHOIS pour {ip}: Fournisseur/Org : {org} | Réseau : {provider} | Abuse : {', '.join(abuse_first) if abuse_first else 'Non trouvée'}"
        return log
    except Exception as e:
        return f"Impossible d'obtenir les infos Whois pour cette IP : {e}"

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
            remarks = contact.get('remarks', []) or []
            for remark in remarks:
                if isinstance(remark, dict):
                    descrs = remark.get('description', []) or []
                    for descr in descrs:
                        for part in descr.split():
                            if '@' in part:
                                all_mails.add(part)
                elif isinstance(remark, str):
                    for part in remark.split():
                        if '@' in part:
                            all_mails.add(part)
        abuse_first = sorted(all_mails, key=lambda m: (not m.lower().startswith('abuse') and 'abuse' not in m.lower(), m))
        print(f"{BLUE}🌍 WHOIS INFOS pour {ip}:{RESET}")
        print(f"   → Fournisseur/Org : {YELLOW}{org}{RESET} | Réseau : {YELLOW}{provider}{RESET}")
        if abuse_first:
            print(f"   → 📧 Abuse : {GREEN}{', '.join(abuse_first)}{RESET}")
        else:
            print(f"   → 📧 Abuse : {RED}Non trouvée{RESET}")
    except Exception as e:
        print_separator("-")
        print(f"{RED}❌ Impossible d'obtenir les infos Whois pour cette IP : {e}{RESET}")
        print_separator("-")

def scan(ip, ports, timeout, logging=False, whois=True):
    log_lines = []
    log_lines.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan de {ip} (timeout {timeout}s) :")
    print_separator("-")
    print(f"🔍 {GREEN}Scan de {ip} (timeout {timeout}s){RESET}")
    print_separator("-")

    def scan_one(args):
        port, proto = args
        url = f"{proto}://{ip}:{port}"
        is_open = is_port_open(ip, port, timeout)
        if is_open and check_protocol(ip, port, proto, timeout):
            return (True, url)
        else:
            return (False, url)

    jobs = [(port, proto) for port in ports for proto in ["http", "https"]]

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        for result, url in executor.map(scan_one, jobs):
            status = f"{GREEN}OUVERT{RESET}" if result else f"{RED}FERMÉ{RESET}"
            print(f"{'✅' if result else '❌'} {url.ljust(28)}  [{status}]")
            log_lines.append(f"{'✅' if result else '❌'} {url}  [{'OUVERT' if result else 'FERMÉ'}]")

    # print_separator("-")
    if whois and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        try:
            whois_str = get_ip_whois_log(ip)
            print_ip_whois(ip)
            log_lines.append(whois_str)
        except Exception as e:
            print_separator("-")
            print(f"{RED}❌ Impossible d'obtenir les infos Whois pour cette IP : {e}{RESET}")
            print_separator("-")
    # print_separator("-")
    if logging:
        write_log('\n'.join(log_lines))

def manage_ports(config):
    print_separator("=")
    print(f"{BLUE}⚙️  Gestion des ports à scanner{RESET}")
    print(f"Ports actuels : {YELLOW}{config['ports']}{RESET}")
    print("1. ➕ Ajouter un port")
    print("2. ➖ Retirer un port")
    print("3. 🔙 Retour\n")
    print_separator("=")

    while True:
        key = readchar.readkey()
        action_done = False
        if key == '1':
            port_input = input("➡️  Entrez un port à ajouter : ").strip()
            if port_input.isdigit():
                port = int(port_input)
                if port not in config['ports']:
                    config['ports'].append(port)
                    save_config(config)
                    print(f"{GREEN}✅ Port {port} ajouté.{RESET}")
                else:
                    print(f"{RED}⚠️  Port déjà présent.{RESET}")
            else:
                print(f"{RED}❌ Invalide.{RESET}")
            input("Appuie sur Entrée pour continuer...")
            print_separator("=")
            action_done = True
        elif key == '2':
            port_input = input("➡️  Entrez un port à retirer : ").strip()
            if port_input.isdigit():
                port = int(port_input)
                if port in config['ports']:
                    config['ports'].remove(port)
                    save_config(config)
                    print(f"{GREEN}✅ Port {port} retiré.{RESET}")
                else:
                    print(f"{RED}⚠️  Ce port n'existe pas.{RESET}")
            else:
                print(f"{RED}❌ Invalide.{RESET}")
            input("Appuie sur Entrée pour continuer...")
            print_separator("=")
            action_done = True
        elif key == '3' or key == readchar.key.ESC:
            if not action_done:
                pass
            break

def manage_timeout(config):
    print_separator("=")
    print(f"{BLUE}⏱️  Timeout actuel : {YELLOW}{config['timeout']} seconde(s){RESET}")
    timeout_input = input("➡️  Entrez un nouveau timeout (en secondes) : ").strip()
    try:
        new_timeout = float(timeout_input)
        if new_timeout > 0:
            config['timeout'] = new_timeout
            save_config(config)
            print(f"{GREEN}✅ Timeout mis à jour : {new_timeout} seconde(s){RESET}")
        else:
            print(f"{RED}❌ Doit être > 0.{RESET}")
    except ValueError:
        print(f"{RED}❌ Nombre invalide.{RESET}")
    input("Appuie sur Entrée pour continuer...")
    print_separator("=")

def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore")
    config = load_config()

    print_banner()
    print_menu(first=True, config=config)

    first_run = True
    while True:
        if not first_run:
            print_menu(first=False, config=config)
        else:
            first_run = False

        key = readchar.readkey()
        if key.lower() == 'p':
            manage_ports(config)
        elif key.lower() == 't':
            manage_timeout(config)
        elif key.lower() == 'l':
            config['logging'] = not config.get('logging', False)
            save_config(config)
            print(f"{GREEN if config['logging'] else RED}Logs {'activés' if config['logging'] else 'désactivés'} !{RESET}")
            print_separator("=")
        elif key.lower() == 'w':
            config['whois'] = not config.get('whois', True)
            save_config(config)
            print(f"{BLUE if config['whois'] else RED}WHOIS {'activé' if config['whois'] else 'désactivé'} !{RESET}")
            print_separator("=")
        elif key == readchar.key.CTRL_C:
            print(f"{RED}\nFermeture du programme.{RESET}")
            break
        else:
            print(key, end="", flush=True)
            ip = key + input()
            target = ip.strip()
            if is_valid_ip_or_domain(target):
                scan(target, config['ports'], config['timeout'],
                     logging=config.get('logging', False),
                     whois=config.get('whois', True))
            else:
                print(f"{RED}❌ Adresse IP ou nom de domaine invalide : {target}{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Arrêt du programme demandé par l'utilisateur (CTRL+C). À bientôt !{RESET}")
        import sys
        sys.exit(0)
