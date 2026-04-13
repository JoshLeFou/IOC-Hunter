"""
Parseur d'IoC robuste avec support du défanging, IPv4/IPv6 et validation stricte.

En CTI, les IoC sont souvent partagés sous forme "défangée" pour éviter
les clics accidentels : hxxps://, [.], etc. Ce module gère la normalisation.
"""

import ipaddress
import re
from typing import Literal

IoCType = Literal[
    "ipv4",
    "ipv6",
    "ip",
    "domain",
    "hash_md5",
    "hash_sha1",
    "hash_sha256",
    "hash",
    "url",
    "unknown",
]


def refang(ioc: str) -> str:
    """
    Transforme un IoC défangé en IoC valide.

    Exemples :
        hxxps://evil[.]com  ->  https://evil.com
        192[.]168[.]1[.]1   ->  192.168.1.1
        evil[.]com          ->  evil.com
    """
    result = ioc.strip()

    # Protocoles
    result = re.sub(
        r"hxxps?://",
        lambda m: m.group(0).replace("xx", "tt"),
        result,
        flags=re.IGNORECASE,
    )
    result = result.replace("hXXp", "http").replace("hXXPs", "https")

    # Points défangés
    result = result.replace("[.]", ".").replace("(.)", ".")

    # Arobase défangé
    result = result.replace("[@]", "@").replace("[at]", "@")

    # Slashes
    result = result.replace("[/]", "/")

    return result


def identify_ioc_type(ioc_raw: str) -> tuple[str, IoCType]:
    """
    Analyse l'entrée utilisateur, la normalise et retourne (ioc_nettoyé, type).

    Returns:
        Tuple (ioc normalisé, type d'IoC).
    """
    ioc = refang(ioc_raw.strip())

    # --- URL complète -> on extrait le domaine/IP pour analyse ---
    url_match = re.match(r"^https?://([^/:]+)", ioc)
    if url_match:
        ioc = url_match.group(1)

    # --- IPv4 strict (avec validation des octets 0-255) ---
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
        try:
            addr = ipaddress.IPv4Address(ioc)
            if not addr.is_private and not addr.is_loopback and not addr.is_reserved:
                return str(addr), "ipv4"
            # On accepte quand même les IPs privées mais on le signale
            return str(addr), "ipv4"
        except ipaddress.AddressValueError:
            pass  # Ce n'est pas une IPv4 valide (ex: 999.999.999.999)

    # --- IPv6 ---
    try:
        addr = ipaddress.IPv6Address(ioc)
        return str(addr), "ipv6"
    except ipaddress.AddressValueError:
        pass

    # --- Hashes (MD5=32, SHA1=40, SHA256=64) ---
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return ioc.lower(), "hash_sha256"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return ioc.lower(), "hash_sha1"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return ioc.lower(), "hash_md5"

    # --- Nom de domaine (support underscore pour _dmarc etc.) ---
    if re.match(r"^([a-zA-Z0-9_]+(-[a-zA-Z0-9_]+)*\.)+[a-zA-Z]{2,}$", ioc):
        return ioc.lower(), "domain"

    return ioc, "unknown"


def is_ip_type(ioc_type: IoCType) -> bool:
    """Vérifie si le type est une adresse IP (v4 ou v6)."""
    return ioc_type in ("ipv4", "ipv6", "ip")


def normalize_ip_type(ioc_type: IoCType) -> str:
    """Normalise ipv4/ipv6 vers 'ip' pour les APIs qui ne différencient pas."""
    if ioc_type in ("ipv4", "ipv6"):
        return "ip"
    if ioc_type.startswith("hash_"):
        return "hash"
    return ioc_type
