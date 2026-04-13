# IOC-Hunter - Investigation technique sur adresses IP

Outil d'investigation CTI interrogeant **6 sources en parallèle** pour répondre aux exigences techniques lors d'opérations CTI sur les adresses IP.

## Architecture

```
cti-tool/
├── main.py                    # Point d'entrée + orchestrateur async
├── config.py                  # Configuration centralisée (clés, timeouts, listes)
├── models.py                  # Modèles de données (dataclasses typées)
├── report.py                  # Affichage Rich + exports JSON/Markdown
├── requirements.txt
├── .env.example               # Template de configuration
├── analyzers/
│   ├── base.py                # Classe abstraite BaseAnalyzer
│   ├── virustotal.py          # VirusTotal API v3 (stats + pDNS + fichiers + certs)
│   ├── abuseipdb.py           # AbuseIPDB (réputation, signalements)
│   ├── shodan_analyzer.py     # Shodan (ports, bannières, headers, JARM, certs)
│   ├── ipinfo.py              # IPInfo (géolocalisation, ASN)
│   ├── whois_analyzer.py      # WHOIS IP via RIR (RDAP/WHOIS natif)
│   └── dns_analyzer.py        # Reverse DNS + résolutions (PTR, A, MX, NS, TXT, SOA)
├── utils/
│   ├── ioc_parser.py          # Parseur IoC robuste (défanging, IPv4/v6, hashes)
│   ├── rate_limiter.py        # Rate limiter async (token bucket)
│   └── http_client.py         # Client HTTP partagé (retry exponentiel, logging)
└── reports/                   # Dossier des rapports générés
```

## Questions généralement couvertes par l'outil

| Question fondamentale                  | Source(s)                |
|----------------------------------------|--------------------------|
| À qui appartient l'IP ?               | WHOIS RIR + IPInfo       |
| Serveur dédié ou mutualisé ?          | pDNS VirusTotal          |
| Géolocalisation ?                      | IPInfo + WHOIS           |
| ASN / contexte réseau ?               | WHOIS + IPInfo           |
| Domaines associés ?                    | Reverse DNS + pDNS VT    |
| Ports ouverts / services / headers ?  | Shodan                   |
| Certificats SSL / JARM ?              | Shodan + VT              |
| Réputation malveillante ?             | VirusTotal + AbuseIPDB   |
| Fichiers communicants ?                | VirusTotal               |

## Installation

```bash
git clone https://github.com/JoshLeFou/IOC-Hunter.git
cd IOC-Hunter
pip install -r requirements.txt
```

## Configuration des clés API

```bash
cp .env.example .env
# Éditez .env avec vos clés
export $(cat .env | xargs)
```

**WHOIS et DNS fonctionnent sans clé API.** Les autres modules nécessitent une inscription gratuite.

## Utilisation

```bash
# Mode interactif
python main.py

# Analyse directe
python main.py 8.8.8.8

# Avec export Markdown
python main.py 185.220.101.1 --markdown

# Sans Shodan (si pas de clé)
python main.py 185.220.101.1 --no-shodan

# Mode silencieux (JSON seul)
python main.py 8.8.8.8 --quiet --json
```

## Test rapide (sans clé API)

WHOIS + DNS fonctionnent toujours :

```bash
python main.py 8.8.8.8 --no-vt --no-shodan --no-abuseipdb --no-ipinfo
```
