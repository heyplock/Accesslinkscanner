# AccessLinkScanner  
*Documentation utilisateur*

---

## Introduction

**AccessLinkScanner (ALS)** est un outil CLI permettant de scanner un ou plusieurs ports sur une adresse IP ou un nom de domaine, afin d’identifier la présence et l’accessibilité de services HTTP ou HTTPS. L’outil permet également d’effectuer des requêtes WHOIS sur les IP scannées, et propose diverses options pour l’affichage, le débogage et la journalisation.

---

## Installation rapide

**Prérequis :**  
- Python 3.x installé  
- Windows, Linux ou macOS

**Installation des librairies nécessaires :**

```bash
pip install requests ipwhois prompt_toolkit
```

Placez le script `ALS.py` dans le dossier de votre choix.

---

## Lancement du programme

Dans le terminal :

```bash
python ALS.py
```

Le menu principal s’affiche avec différentes options.

---

## Menu principal

- **S**canner une IP ou un domaine : tapez simplement l’IP ou le domaine puis Entrée.
- **P**orts : ajouter ou retirer les ports à scanner.
- **T**imeout : définir le délai maximal (en secondes) pour chaque test de port/service.
- **L**ogs : activer/désactiver l’écriture des résultats de scan dans le fichier `scan.log`.
- **W**HOIS : activer/désactiver l’affichage et l’enregistrement des infos WHOIS.
- **D**ebug : activer/désactiver l’affichage détaillé pour le débogage.
- **Q**uitter : quitter le programme.

---

## Fonctionnement du scan d’IP/port

Pour chaque port (en `http` et `https`) :

1. **Connexion TCP :**  
   - Le programme tente d’ouvrir une connexion TCP (`socket.connect`) à l’IP et au port spécifiés.
   - Si la connexion TCP échoue (refus, absence de réponse ou timeout), le port est affiché comme **FERMÉ**.

2. **Test du service HTTP/HTTPS :**  
   - Si la connexion TCP réussit, l’outil envoie une requête HTTP ou HTTPS en mode « streaming » :
     - **HTTPS :** utilise un contexte SSL permissif (accepte legacy renegotiation et les certificats auto-signés).
     - Les redirections ne sont **pas suivies**.
   - Si un code HTTP est reçu (200, 301, 302, 403, 500, etc.), le port est affiché comme **OUVERT**.
   - Si le serveur ne répond pas dans le délai, ou si le handshake TLS échoue, le port est affiché comme **ERREUR**.

3. **Temps de réponse :**  
   - Le temps affiché (ex. `[32 ms]`) correspond au temps de connexion TCP (latence réseau).

4. **Affichage final :**  
   - Chaque ligne affiche le protocole, l’URL, l’état (OUVERT/FERMÉ/ERREUR) et le temps.

**Résumé des états possibles :**

| Statut   | Description                                           |
|----------|------------------------------------------------------|
| **OUVERT**   | Connexion TCP réussie + réponse HTTP reçue           |
| **FERMÉ**    | Connexion TCP impossible (port réellement fermé)      |
| **ERREUR**   | TCP ok mais HTTP/TLS échoue (timeout/handshake…)     |

---

## Fonctionnement du WHOIS

- Si le WHOIS est activé, le programme effectue une requête WHOIS pour chaque IP scannée.
- Il récupère :
  - Le nom du fournisseur ou de l’organisation (`org` ou `network name`)
  - L’adresse e-mail de contact ou d’abuse (si disponible)
- Les informations sont affichées et éventuellement enregistrées dans le log si activé.

**Le WHOIS permet d’identifier le propriétaire d’une IP en cas d’incident réseau ou d’activité suspecte.**

---

## Fichier de configuration

Un fichier `config.json` est créé dans `Documents/AccessLinkScanner/` pour mémoriser vos préférences (ports, timeout, options actives).  
Modifiable à la main ou via le menu.

Exemple :

```json
{
    "ports": [80, 443, 8080, 48443],
    "timeout": 5,
    "logging": false,
    "whois": true,
    "debug": false
}
```

---

## Options avancées

- **Logs :** si activé, tous les résultats de scan sont ajoutés à `scan.log`.
- **Debug :** affiche les détails des requêtes HTTP (codes, exceptions) pour le diagnostic.
- **Timeout :** peut être augmenté si certains équipements sont lents à répondre.

---

## Limitations connues

- Le scan ne teste que les services HTTP/HTTPS (pas SMTP, FTP, etc.).
- Certains équipements anciens ou atypiques peuvent nécessiter d’augmenter le timeout ou ne pas répondre même en mode permissif.
- La résolution DNS dépend du système d’exploitation.

---

## Support & évolutions

Pour signaler un bug ou proposer une évolution :  
[https://github.com/heyplock/Accesslinkscanner](https://github.com/heyplock/Accesslinkscanner)

---

**Fin du document**
