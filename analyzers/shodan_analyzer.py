"""
Analyseur Shodan - Profiling du serveur.

Répond aux questions :
- Quels ports sont ouverts ?
- Quels services tournent (versions, bannières) ?
- Quels certificats SSL sont présents ?
- Quelle est l'empreinte JARM du serveur ?
- Quels headers HTTP sont renvoyés ?
"""

import logging
from typing import Optional

from models import AnalyzerError, PortInfo, ShodanResult, SSLCertificate
from utils.http_client import fetch_json

from .base import BaseAnalyzer

logger = logging.getLogger("Shodan")


class ShodanAnalyzer(BaseAnalyzer):
    name = "Shodan"
    requires_api_key = True

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key)

    async def analyze(
        self, ip: str
    ) -> tuple[Optional[ShodanResult], Optional[AnalyzerError]]:
        if not self.is_configured:
            return None, self._make_error(
                "CONFIG", "Clé API Shodan manquante (SHODAN_API_KEY)"
            )

        logger.info(f"Scan de {ip}...")

        data, err = await fetch_json(
            url=f"{self.BASE_URL}/shodan/host/{ip}",
            params={"key": self.api_key},
            source_name="Shodan",
        )

        if err:
            return None, self._make_error("API", err)

        # --- Construction du résultat ---
        result = ShodanResult(
            ip=ip,
            hostnames=data.get("hostnames", []),
            os=data.get("os", "") or "",
            tags=data.get("tags", []),
            vulns=list(data.get("vulns", {}).keys())
            if isinstance(data.get("vulns"), dict)
            else data.get("vulns", []),
            last_update=data.get("last_update", ""),
        )

        # --- Extraction des ports, services et certificats ---
        for service in data.get("data", []):
            port_info = PortInfo(
                port=service.get("port", 0),
                protocol=service.get("transport", "tcp"),
                service=service.get("product", "")
                or service.get("_shodan", {}).get("module", ""),
                product=service.get("product", "") or "",
                version=service.get("version", "") or "",
                banner=_truncate(service.get("data", ""), 500),
                cpe=service.get("cpe", []) or [],
            )
            result.ports.append(port_info)

            # Extraction des certificats SSL si présents
            ssl_info = service.get("ssl", {})
            if ssl_info:
                cert_data = ssl_info.get("cert", {})
                subject = cert_data.get("subject", {})
                issuer = cert_data.get("issuer", {})

                cert = SSLCertificate(
                    serial=str(cert_data.get("serial", "")),
                    issuer=issuer.get("CN", "") or issuer.get("O", ""),
                    subject=subject.get("CN", "") or subject.get("O", ""),
                    subject_alt_names=cert_data.get("extensions", {}).get(
                        "subjectAltName", []
                    )
                    if isinstance(cert_data.get("extensions"), dict)
                    else [],
                    valid_from=str(cert_data.get("notBefore", "")),
                    valid_to=str(cert_data.get("notAfter", "")),
                    fingerprint_sha256=cert_data.get("fingerprint", {}).get(
                        "sha256", ""
                    ),
                    jarm=ssl_info.get("jarm", "") or "",
                    ja3s=ssl_info.get("ja3s", "") or "",
                )
                result.certificates.append(cert)

        logger.info(
            f"✓ Shodan terminé - {len(result.ports)} ports ouverts, "
            f"{len(result.certificates)} certificats, "
            f"{len(result.vulns)} CVEs"
        )
        return result, None


def _truncate(text: str, max_len: int) -> str:
    """Tronque un texte (bannières Shodan très longues)."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…[tronqué]"
