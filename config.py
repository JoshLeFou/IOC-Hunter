"""
Configuration centrale du projet IOC-Hunter.
Toutes les clés API, timeouts, et paramètres globaux sont centralisés ici.
"""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# RÉPERTOIRES
# =============================================================================
PROJECT_ROOT = Path(__file__).parent
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# =============================================================================
# LOGGING - Traçabilité des recherches
# =============================================================================
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(REPORTS_DIR / "investigation.log", encoding="utf-8"),
    ],
)


# =============================================================================
# CLÉS API - Lues depuis les variables d'environnement
# Pour configurer : export VT_API_KEY="xxx" (ou fichier .env)
# =============================================================================
API_KEYS = {
    "virustotal": os.environ.get("VT_API_KEY", ""),
    "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", ""),
    "shodan": os.environ.get("SHODAN_API_KEY", ""),
    "ipinfo": os.environ.get("IPINFO_TOKEN", ""),
}

# =============================================================================
# TIMEOUTS & RETRY (robustesse production)
# =============================================================================
HTTP_TIMEOUT = 25.0  # secondes - VT peut être lent
MAX_RETRIES = 3  # nombre de tentatives par requête
RETRY_BACKOFF = 2.0  # multiplicateur exponentiel entre retries
VT_RATE_LIMIT = 4  # requêtes par minute (clé gratuite VT)
VT_RATE_WINDOW = 60  # fenêtre en secondes

# =============================================================================
# LISTES DE RÉFÉRENCE (pièges courants)
# =============================================================================
# Services de DNS dynamiques - NE PAS pivoter sur le domaine parent
DYNAMIC_DNS_DOMAINS = {
    "bounceme.net",
    "zyns.com",
    "changeip.org",
    "chickenkiller.com",
    "ddns.net",
    "ezua.com",
    "freetcp.com",
    "got-game.org",
    "homeftp.org",
    "homeip.net",
    "faqserv.com",
    "publicvm.com",
    "homelinux.com",
    "hobby-site.org",
    "zzux.com",
    "homedns.org",
    "linkpc.net",
    "mefound.com",
    "myftp.org",
    "organiccrap.com",
    "otzo.com",
    "redirectme.net",
    "servemp3.com",
    "selfip.info",
    "sendsmtp.com",
    "servebbs.com",
    "servehttp.com",
    "serveusers.com",
    "sytes.net",
    "yourtrap.com",
    "zapto.org",
    "mooo.com",
    "ignorelist.com",
    "strangled.net",
    "3utilities.com",
    "no-ip.com",
    "no-ip.org",
    "duckdns.org",
    "dynu.com",
    "freedns.afraid.org",
}

# Hébergeurs connus - pour distinguer serveur dédié vs cloud
KNOWN_HOSTING_PROVIDERS = {
    "OVH",
    "OVHcloud",
    "Amazon",
    "AWS",
    "Microsoft",
    "Azure",
    "Google",
    "GCP",
    "DigitalOcean",
    "Linode",
    "Akamai",
    "Vultr",
    "Hetzner",
    "Choopa",
    "Cloudflare",
    "Fastly",
    "G-Core",
    "Scaleway",
    "Contabo",
    "HostGator",
}

# Sinkhole providers connus
KNOWN_SINKHOLES = {
    "sinkhole.tech",
    "sinkdns.org",
    "shadowserver.org",
}
