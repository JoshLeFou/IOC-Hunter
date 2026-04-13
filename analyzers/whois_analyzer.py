"""
Analyseur WHOIS IP - Interrogation directe des registres RIR.

N'utilise pas d'API externe payante : s'appuie sur la librairie ipwhois
qui interroge directement les serveurs WHOIS des RIR (RIPE, ARIN, APNIC, etc.)

Répond aux questions du style :
- À qui appartient l'adresse IP ? (organisation, plage réseau)
- Quel ASN annonce cette plage ?
- Quelle est la plage d'adresses ?
- Quand a été allouée l'adresse ?
"""

import asyncio
import logging
from typing import Optional

from models import AnalyzerError, WhoisInfo

from .base import BaseAnalyzer

logger = logging.getLogger("WHOIS_IP")


class WhoisAnalyzer(BaseAnalyzer):
    name = "WHOIS_IP"
    requires_api_key = False  # Pas besoin de clé API

    def __init__(self, api_key: str = ""):
        super().__init__(api_key)

    async def analyze(
        self, ip: str
    ) -> tuple[Optional[WhoisInfo], Optional[AnalyzerError]]:
        logger.info(f"Requête WHOIS pour {ip}...")

        try:
            # ipwhois est synchrone, on l'exécute dans un thread pour ne pas bloquer
            result = await asyncio.to_thread(self._do_whois, ip)
            return result, None
        except Exception as exc:
            logger.error(f"Erreur WHOIS : {exc}")
            return None, self._make_error("WHOIS", str(exc))

    @staticmethod
    def _do_whois(ip: str) -> WhoisInfo:
        """Exécution synchrone de la requête WHOIS (dans un thread séparé)."""
        from ipwhois import IPWhois

        obj = IPWhois(ip)
        # rdap est plus fiable et plus riche que whois classique
        try:
            data = obj.lookup_rdap(depth=1)
        except Exception:
            # Fallback sur whois classique si RDAP échoue
            data = obj.lookup_whois()

        # Extraction de l'ASN
        asn = 0
        try:
            asn = int(data.get("asn", 0))
        except (ValueError, TypeError):
            pass

        # Extraction du réseau
        network = data.get("network", {}) or {}

        # Extraction du CIDR
        cidr = data.get("asn_cidr", "")
        if not cidr:
            cidr = network.get("cidr", "")

        # Extraction défensive - ipwhois renvoie souvent None au lieu de [] ou {}
        description = ""
        remarks = network.get("remarks") or []
        if remarks and isinstance(remarks[0], dict):
            description = remarks[0].get("description", "") or ""

        registration_date = ""
        events = network.get("events") or []
        if events and isinstance(events[0], dict):
            registration_date = events[0].get("timestamp", "") or ""

        result = WhoisInfo(
            ip=ip,
            network_name=network.get("name", "") or "",
            network_range=cidr,
            description=description,
            country=network.get("country", "")
            or data.get("asn_country_code", "")
            or "",
            organization=data.get("asn_description", "") or "",
            asn=asn,
            asn_description=data.get("asn_description", "") or "",
            abuse_contact=_extract_abuse_email(data),
            registration_date=registration_date,
            last_modified="",
        )

        logger.info(
            f"✓ WHOIS terminé - {result.organization} (AS{result.asn}), "
            f"Réseau: {result.network_range}, Pays: {result.country}"
        )
        return result


def _extract_abuse_email(data: dict) -> str:
    """Extrait l'email d'abus depuis les données WHOIS."""
    import re

    # Tente d'abord les objets réseau
    objects = data.get("objects") or {}
    for obj_key, obj_val in objects.items():
        if not isinstance(obj_val, dict):
            continue
        contact = obj_val.get("contact") or {}
        if not isinstance(contact, dict):
            continue
        email_list = contact.get("email") or []
        if not isinstance(email_list, list):
            continue
        for entry in email_list:
            if isinstance(entry, dict):
                email = entry.get("value", "") or ""
            elif entry is not None:
                email = str(entry)
            else:
                continue
            if "abuse" in email.lower():
                return email

    # Fallback sur les champs réseau
    network = data.get("network") or {}
    remarks = network.get("remarks") or []
    if not isinstance(remarks, list):
        remarks = []
    for remark in remarks:
        if not isinstance(remark, dict):
            continue
        desc = remark.get("description", "") or ""
        if "abuse" in desc.lower() and "@" in desc:
            emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", desc)
            if emails:
                return emails[0]

    return ""
