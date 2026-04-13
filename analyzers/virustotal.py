"""
Analyseur VirusTotal - API v3.

Extrait :
- Statistiques de détection (last_analysis_stats)
- Réputation communautaire
- DNS passif (resolutions)
- Fichiers communicants (communicating_files)
- Certificats SSL historiques
- Informations réseau (ASN, pays)
"""

import logging
from typing import Optional

from config import VT_RATE_LIMIT, VT_RATE_WINDOW
from models import AnalyzerError, VTAnalysisStats, VTResult
from utils.http_client import fetch_json
from utils.rate_limiter import AsyncRateLimiter

from .base import BaseAnalyzer

logger = logging.getLogger("VirusTotal")

# Rate limiter partagé par toutes les requêtes VT de cette session
_vt_limiter = AsyncRateLimiter(max_calls=VT_RATE_LIMIT, period=VT_RATE_WINDOW)


class VirusTotalAnalyzer(BaseAnalyzer):
    name = "VirusTotal"
    requires_api_key = True

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key)
        self.headers = {"x-apikey": self.api_key}

    async def _vt_get(self, endpoint: str) -> tuple[Optional[dict], Optional[str]]:
        """Requête GET vers VT avec rate limiting."""
        async with _vt_limiter:
            return await fetch_json(
                url=f"{self.BASE_URL}{endpoint}",
                headers=self.headers,
                source_name="VirusTotal",
            )

    async def analyze(
        self, ip: str
    ) -> tuple[Optional[VTResult], Optional[AnalyzerError]]:
        if not self.is_configured:
            return None, self._make_error("CONFIG", "Clé API VT manquante (VT_API_KEY)")

        logger.info(f"Analyse de {ip}...")

        # --- 1. Données principales de l'IP ---
        data, err = await self._vt_get(f"/ip_addresses/{ip}")
        if err:
            return None, self._make_error("API", err)

        attrs = data.get("data", {}).get("attributes", {})
        stats_raw = attrs.get("last_analysis_stats", {})

        result = VTResult(
            ip=ip,
            stats=VTAnalysisStats(
                malicious=stats_raw.get("malicious", 0),
                suspicious=stats_raw.get("suspicious", 0),
                undetected=stats_raw.get("undetected", 0),
                harmless=stats_raw.get("harmless", 0),
                timeout=stats_raw.get("timeout", 0),
            ),
            reputation=attrs.get("reputation", 0),
            as_owner=attrs.get("as_owner", ""),
            country=attrs.get("country", ""),
            link=f"https://www.virustotal.com/gui/ip-address/{ip}",
        )

        # --- 2. DNS passif (resolutions) ---
        # pDNS peut être utilisé comme pivot
        pdns_data, pdns_err = await self._vt_get(
            f"/ip_addresses/{ip}/resolutions?limit=20"
        )
        if not pdns_err and pdns_data:
            for item in pdns_data.get("data", []):
                entry_attrs = item.get("attributes", {})
                result.passive_dns.append(
                    {
                        "hostname": entry_attrs.get("host_name", ""),
                        "date": entry_attrs.get("date", 0),
                    }
                )

        # --- 3. Fichiers communicants ---
        # Quels fichiers malveillants contactent cette IP ?
        files_data, files_err = await self._vt_get(
            f"/ip_addresses/{ip}/communicating_files?limit=10"
        )
        if not files_err and files_data:
            for item in files_data.get("data", []):
                f_attrs = item.get("attributes", {})
                f_stats = f_attrs.get("last_analysis_stats", {})
                result.communicating_files.append(
                    {
                        "sha256": item.get("id", ""),
                        "name": f_attrs.get(
                            "meaningful_name", f_attrs.get("name", "N/A")
                        ),
                        "type": f_attrs.get("type_description", ""),
                        "malicious": f_stats.get("malicious", 0),
                        "total": sum(f_stats.values()) if f_stats else 0,
                        "first_seen": f_attrs.get("first_submission_date", ""),
                    }
                )

        # --- 4. Certificats SSL historiques ---
        certs_data, certs_err = await self._vt_get(
            f"/ip_addresses/{ip}/historical_ssl_certificates?limit=10"
        )
        if not certs_err and certs_data:
            for item in certs_data.get("data", []):
                c_attrs = item.get("attributes", {})
                subject = c_attrs.get("subject", {})
                issuer = c_attrs.get("issuer", {})
                result.certificates.append(
                    {
                        "thumbprint": c_attrs.get("thumbprint_sha256", ""),
                        "subject_cn": subject.get("CN", ""),
                        "issuer_cn": issuer.get("CN", ""),
                        "validity_not_before": c_attrs.get("validity", {}).get(
                            "not_before", ""
                        ),
                        "validity_not_after": c_attrs.get("validity", {}).get(
                            "not_after", ""
                        ),
                    }
                )

        logger.info(
            f"✓ VT terminé - Détection: {result.stats.detection_ratio}, "
            f"pDNS: {len(result.passive_dns)} entrées, "
            f"Fichiers communicants: {len(result.communicating_files)}"
        )
        return result, None
