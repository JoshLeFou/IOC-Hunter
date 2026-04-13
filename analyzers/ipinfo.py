"""
Analyseur IPInfo - Géolocalisation et contexte réseau.

Répond aux questions :
- Où est géolocalisé le serveur ?
- Quel ASN gère le routage ?
- À quelle organisation est attribuée l'IP ?
- Quel est le type d'usage (hébergeur, FAI, entreprise) ?
"""

import logging
from typing import Optional

from models import AnalyzerError, GeoLocation
from utils.http_client import fetch_json

from .base import BaseAnalyzer

logger = logging.getLogger("IPInfo")


class IPInfoAnalyzer(BaseAnalyzer):
    name = "IPInfo"
    requires_api_key = True

    BASE_URL = "https://ipinfo.io"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key)

    async def analyze(
        self, ip: str
    ) -> tuple[Optional[GeoLocation], Optional[AnalyzerError]]:
        if not self.is_configured:
            return None, self._make_error(
                "CONFIG", "Token IPInfo manquant (IPINFO_TOKEN)"
            )

        logger.info(f"Géolocalisation de {ip}...")

        data, err = await fetch_json(
            url=f"{self.BASE_URL}/{ip}",
            params={"token": self.api_key},
            source_name="IPInfo",
        )

        if err:
            return None, self._make_error("API", err)

        # Parsing des coordonnées "lat,lng"
        loc = data.get("loc", "0,0").split(",")
        lat = float(loc[0]) if len(loc) >= 1 else 0.0
        lng = float(loc[1]) if len(loc) >= 2 else 0.0

        # Parsing de l'ASN (format "AS12345 Nom de l'AS")
        org_raw = data.get("org", "")
        as_number = 0
        as_name = org_raw
        if org_raw.startswith("AS"):
            parts = org_raw.split(" ", 1)
            try:
                as_number = int(parts[0][2:])
                as_name = parts[1] if len(parts) > 1 else ""
            except ValueError:
                pass

        result = GeoLocation(
            ip=ip,
            city=data.get("city", ""),
            region=data.get("region", ""),
            country=data.get("country", ""),
            country_code=data.get("country", ""),
            latitude=lat,
            longitude=lng,
            timezone=data.get("timezone", ""),
            isp=data.get("org", ""),
            org=data.get("company", {}).get("name", "")
            if isinstance(data.get("company"), dict)
            else "",
            as_number=as_number,
            as_name=as_name,
        )

        logger.info(
            f"✓ IPInfo terminé - {result.city}, {result.country} (AS{result.as_number})"
        )
        return result, None
