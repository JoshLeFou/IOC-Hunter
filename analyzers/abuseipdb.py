"""
Analyseur AbuseIPDB - Réputation et signalements d'abus.

AbuseIPDB fournit un score de confiance basé sur les signalements
de la communauté (brute force, spam, scanning, etc.)
"""

import logging
from typing import Optional

from models import AbuseIPDBResult, AnalyzerError
from utils.http_client import fetch_json

from .base import BaseAnalyzer

logger = logging.getLogger("AbuseIPDB")

# Mapping des catégories d'abus AbuseIPDB
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBAnalyzer(BaseAnalyzer):
    name = "AbuseIPDB"
    requires_api_key = True

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key)

    async def analyze(
        self, ip: str
    ) -> tuple[Optional[AbuseIPDBResult], Optional[AnalyzerError]]:
        if not self.is_configured:
            return None, self._make_error(
                "CONFIG", "Clé API AbuseIPDB manquante (ABUSEIPDB_API_KEY)"
            )

        logger.info(f"Vérification de {ip}...")

        data, err = await fetch_json(
            url=self.BASE_URL,
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "",
            },
            source_name="AbuseIPDB",
        )

        if err:
            return None, self._make_error("API", err)

        report = data.get("data", {})

        # Résolution des catégories numériques en labels lisibles
        raw_categories = []
        for r in report.get("reports", []):
            raw_categories.extend(r.get("categories", []))
        category_names = sorted(
            set(ABUSE_CATEGORIES.get(c, f"Catégorie #{c}") for c in raw_categories)
        )

        result = AbuseIPDBResult(
            ip=ip,
            is_public=report.get("isPublic", True),
            abuse_confidence_score=report.get("abuseConfidenceScore", 0),
            total_reports=report.get("totalReports", 0),
            num_distinct_users=report.get("numDistinctUsers", 0),
            last_reported_at=report.get("lastReportedAt", ""),
            isp=report.get("isp", ""),
            domain=report.get("domain", ""),
            country_code=report.get("countryCode", ""),
            usage_type=report.get("usageType", ""),
            is_whitelisted=report.get("isWhitelisted", False),
            categories=category_names,
        )

        logger.info(
            f"✓ AbuseIPDB terminé - Score: {result.abuse_confidence_score}%, "
            f"Signalements: {result.total_reports}"
        )
        return result, None
