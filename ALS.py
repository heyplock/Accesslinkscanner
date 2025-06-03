import socket
import requests
import urllib3
import json
import re
from pathlib import Path
import os
import concurrent.futures
from ipwhois import IPWhois
import warnings
from datetime import datetime
from prompt_toolkit import PromptSession
import ssl
import threading
import time

from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# === Configuration et Chemins ===
session = PromptSession()
warnings.filterwarnings("ignore")

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
    "whois": True,
    "debug": False
}


# === Fonctions de gestion du fichier de configuration ===
def load_config():
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()


def save_config(config):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)


# === Fonctions d’affichage (bannières, séparateurs, menus) ===
def print_separator(style="-"):
    print("\n" + style * SEP_WIDTH + "\n")


def print_banner():
    print_separator("=")
    print(f"{GREEN}🛠️  Multitool - Scanner HTTP/HTTPS stylisé{RESET}")
    print_separator("=")


def print_menu(first=False, config=None):
    if first:
        # Premier affichage : on indique juste la ligne d’invite initiale
        print(f"{YELLOW}👉 Entrez une adresse IP ou un nom de domaine{RESET}")
        print(f"{RED}📌 Tape 'P' pour gérer les ports, 'T' pour le timeout, 'L' pour logs, 'W' pour WHOIS, 'D' pour Debug{RESET}\n")
    else:
        # À chaque nouvelle itération, on réaffiche l’invite avec le statut actuel des flags
        line = f"{YELLOW}👉 Entrez une adresse IP ou un nom de domaine{RESET}"
        if config is not None:
            if config.get('logging'):
                line += f"   {GREEN}[LOG ACTIF]{RESET}"
            if config.get('whois', True):
                line += f"   {BLUE}[WHOIS ON]{RESET}"
            else:
                line += f"   {RED}[WHOIS OFF]{RESET}"
            if config.get('debug', False):
                line += f"   {YELLOW}[DEBUG ON]{RESET}"
            else:
                line += f"   {RED}[DEBUG OFF]{RESET}"
        print(line)


# === Validation d’IP / domaine ===
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


# === Gestion des ports (menu) ===
def manage_ports(config):
    print_separator("=")
    print(f"{BLUE}⚙️  Gestion des ports à scanner{RESET}")
    print(f"Ports actuels : {YELLOW}{config['ports']}{RESET}")
    print("1. ➕ Ajouter un port")
    print("2. ➖ Retirer un port")
    print("3. 🔙 Retour\n")
    print_separator("=")

    while True:
        key = session.prompt("Choix (1/2/3) → ").strip()
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

        elif key == '3':
            if not action_done:
                pass
            break

        else:
            print(f"{RED}❌ Choix invalide (1, 2 ou 3).{RESET}")


# === Gestion du timeout (menu) ===
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


# === Fonction pour écrire le log dans un fichier ===
def write_log(content):
    log_path = CONFIG_PATH.parent / "scan.log"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(content + "\n")


# === Fonction WHOIS pour une IP ===
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
        log = f"WHOIS pour {ip}: Fournisseur/Org : {org} | Réseau : {provider} | Abuse : {', '.join(abuse_first) if abuse_first else 'Non trouvée'}"
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


# ──────────────────────────────────────────────────────────────────────────────
#   SSLAdapter : adapter pour requests afin d'utiliser un SSLContext "insecure"
#   et d'autoriser la legacy renegotiation (si supportée)
# ──────────────────────────────────────────────────────────────────────────────
class SSLAdapter(HTTPAdapter):
    """
    Un adapter pour requests qui utilise un SSLContext personnalisé.
    Cet adapter permet notamment de :
      - désactiver la vérification de certificat (CERT_NONE),
      - désactiver le check_hostname,
      - activer OP_LEGACY_SERVER_CONNECT si disponible (legacy renegotiation).
    """
    def __init__(self, ssl_context, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        # Crée un PoolManager qui utilise notre SSLContext personnalisé
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=self.ssl_context
        )


# ──────────────────────────────────────────────────────────────────────────────
#   scan : fonction principale de scan, avec flag `debug` optionnel
# ──────────────────────────────────────────────────────────────────────────────
def scan(ip, ports, timeout, logging=False, whois=True, debug=False):
    """
    ip       : adresse IP ou domaine à scanner
    ports    : liste de ports (ints)
    timeout  : durée max (en secondes) pour le TCP CONNECT et le GET HTTP
    logging  : bool – si True, écrit le log complet dans scan.log
    whois    : bool – si True, affiche et logge les infos WHOIS
    debug    : bool – si True, affiche les DEBUG: GET … / exceptions
    """

    # 1) Création d’un SSLContext qui désactive la vérification de certificat et autorise legacy renegotiation
    ssl_ctx = ssl.create_default_context()

    # Désactivation du check_hostname
    ssl_ctx.check_hostname = False
    # Désactivation totale de la vérification de certificat
    ssl_ctx.verify_mode = ssl.CERT_NONE

    # Si OpenSSL/Python supporte OP_LEGACY_SERVER_CONNECT, on l’active
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        ssl_ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT

    # ─── Spinner animé pendant le scan ───
    def spinner_task(stop_event, msg):
        spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
        idx = 0
        while not stop_event.is_set():
            print(f"\r{GREEN}{spinner[idx % len(spinner)]} {msg}{RESET}", end="", flush=True)
            idx += 1
            time.sleep(0.1)
        # Efface la ligne du spinner à l'arrêt
        print('\r' + ' ' * (len(msg) + 5) + '\r', end='', flush=True)

    # Journalisation initiale
    log_lines = []
    log_lines.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan de {ip} (timeout {timeout}s) :")
    print_separator("-")

    # Démarrage du spinner
    msg = f"Scan de {ip} (timeout {timeout}s)"
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner_task, args=(stop_event, msg))
    spinner_thread.start()

    # ─── check_service_any_response : GET en streaming (sans redirect) en HTTPS/HTTP ───
    def check_service_any_response(url, timeout_http):
        """
        Tente un GET en streaming (stream=True) sans suivre les redirections (allow_redirects=False).
        Utilise une Session qui monte notre SSLAdapter avec le SSLContext “insecure” configuré ci-dessus.

        - Si on reçoit un code HTTP (1xx–5xx) dans le délai `timeout_http` → retourne True (port ouvert).
        - Si on reçoit une exception (timeout HTTP ou handshake TLS KO) → retourne False (ERREUR).
        Affiche en debug le status_code ou l'exception, si debug=True.
        """
        try:
            sess = requests.Session()
            # Monte l’adapter HTTPS sur notre SSLContext personnalisé
            sess.mount("https://", SSLAdapter(ssl_ctx))

            # Exécute le GET en streaming, sans redirection
            resp = sess.get(
                url,
                timeout=timeout_http,      # on laisse le même timeout que pour TCP
                verify=False,              # ignore le certificat auto-signé
                stream=True,               # on ne télécharge que les en-têtes
                allow_redirects=False      # ne pas suivre la redirection 302/301
            )
            # Si le mode debug est activé, on affiche le code HTTP
            if debug:
                print(f"{YELLOW}DEBUG:{RESET} GET {url} → status_code={resp.status_code}")
            # Toute réponse HTTP 1xx–5xx signifie “service existant” → “open”
            return True
        except Exception as e:
            if debug:
                print(f"{YELLOW}DEBUG:{RESET} GET {url} a levé : {e}")
            return False

    # ─── scan_one : test d’un seul port (TCP + HTTP/HTTPS) ───
    def scan_one(args):
        port, proto = args
        url = f"{proto}://{ip}:{port}"

        # 1) Test TCP (socket.connect) pour mesurer la latence “pure”
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            connect_time = int((time.perf_counter() - start) * 1000)  # latence TCP en ms
            sock.close()
        except (socket.timeout, socket.error):
            # Pas de connexion TCP → port “closed”
            sock.close()
            return ("closed", url, None)

        # 2) Port TCP ouvert → on teste HTTP/HTTPS en streaming (avec SSLAdapter)
        service_ok = check_service_any_response(url, timeout_http=timeout)
        if service_ok:
            # Si on reçoit un code HTTP (1xx–5xx) → port “open”
            return ("open", url, f"{connect_time} ms")
        else:
            # GET a planté (timeout > timeout_http, handshake TLS KO, etc.) → “error”
            return ("error", url, f"{connect_time} ms")

    # Génère la liste des jobs (chaque port testé en HTTP & HTTPS)
    jobs = [(port, proto) for port in ports for proto in ["http", "https"]]

    # ─── Lancement du scan multithread ───
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(scan_one, jobs))

    # Arrêt du spinner
    stop_event.set()
    spinner_thread.join()

    # ─── Affichage final ───
    for result, url, timeinfo in results:
        if result == "open":
            symbol = "🟢"
            status = f"{GREEN}OUVERT{RESET}"
        elif result == "error":
            symbol = "🟡"
            status = f"{YELLOW}ERREUR{RESET}"
        else:  # "closed"
            symbol = "🔴"
            status = f"{RED}FERMÉ{RESET}"

        if timeinfo is None:
            timing_str = ""  # pas de timing pour CLOSED
        else:
            timing_str = f"[{YELLOW}{timeinfo}{RESET}]"

        print(f"{symbol} {url.ljust(28)} [{status}] {timing_str}")
        log_lines.append(f"{symbol} {url.ljust(28)} [{status}] {timing_str}")

    # ─── WHOIS (si activé) ───
    if whois and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        try:
            whois_str = get_ip_whois_log(ip)
            print_ip_whois(ip)
            log_lines.append(whois_str)
        except Exception as e:
            print_separator("-")
            print(f"{RED}❌ Impossible d'obtenir les infos Whois pour cette IP : {e}{RESET}")

    # ─── Écriture du log (si demandé) ───
    if logging:
        write_log('\n'.join(log_lines))


# === Fonction MAIN CLI ===
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

        # Prompt unique pour menu + saisie des IP/domaines
        user_input = session.prompt(
            f"\n[P]orts / [T]imeout / [L]ogs / [W]hois / [D]ebug / [Q]uitter\n→ "
        ).strip()
        c = user_input.lower()

        if not c:
            continue

        # Quitter
        if c in ['q', 'quit', 'exit']:
            print(f"{RED}\nFermeture du programme.{RESET}")
            break

        # Gérer les ports
        elif c == 'p':
            manage_ports(config)

        # Gérer le timeout
        elif c == 't':
            manage_timeout(config)

        # Activer/Désactiver les logs
        elif c == 'l':
            config['logging'] = not config.get('logging', False)
            save_config(config)
            print(f"{GREEN if config['logging'] else RED}Logs {'activés' if config['logging'] else 'désactivés'} !{RESET}")
            print_separator("=")

        # Activer/Désactiver le WHOIS
        elif c == 'w':
            config['whois'] = not config.get('whois', True)
            save_config(config)
            print(f"{BLUE if config['whois'] else RED}WHOIS {'activé' if config['whois'] else 'désactivé'} !{RESET}")
            print_separator("=")

        # Activer/Désactiver le Debug
        elif c == 'd':
            config['debug'] = not config.get('debug', False)
            save_config(config)
            print(f"{YELLOW if config['debug'] else RED}DEBUG {'activé' if config['debug'] else 'désactivé'} !{RESET}")
            print_separator("=")

        # Sinon, on suppose qu'on a une IP ou un domaine à scanner
        else:
            target = user_input
            if is_valid_ip_or_domain(target):
                scan(
                    target,
                    config['ports'],
                    config['timeout'],
                    logging=config.get('logging', False),
                    whois=config.get('whois', True),
                    debug=config.get('debug', False)
                )
            else:
                print(f"{RED}❌ Commande ou IP/domain invalide : {target}{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Arrêt du programme demandé par l'utilisateur (CTRL+C). À bientôt !{RESET}")
        import sys
        sys.exit(0)
