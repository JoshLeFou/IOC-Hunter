"""
Analyseur DNS - Reverse DNS et résolutions.

Répond aux questions :
- Quel est l'enregistrement PTR (reverse DNS) de cette IP ?
- Quels noms de domaines sont associés ?
"""

import asyncio
import logging
import socket
from typing import Optional

import dns.resolver
import dns.reversename

from models import AnalyzerError, DNSRecord, ReverseDNSResult

from .base import BaseAnalyzer

logger = logging.getLogger("DNS")


class DNSAnalyzer(BaseAnalyzer):
    name = "DNS"
    requires_api_key = False  # Utilise les résolveurs DNS publics

    def __init__(self, api_key: str = ""):
        super().__init__(api_key)
        # Résolveur DNS configuré avec des serveurs publics fiables
        # configure=False pour ne pas dépendre de /etc/resolv.conf
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        self.resolver.timeout = 10
        self.resolver.lifetime = 15

    async def analyze(
        self, ip: str
    ) -> tuple[Optional[ReverseDNSResult], Optional[AnalyzerError]]:
        logger.info(f"Résolution DNS inverse pour {ip}...")

        result = ReverseDNSResult(ip=ip)

        try:
            # Toutes les opérations DNS sont bloquantes, on les exécute dans un thread
            result = await asyncio.to_thread(self._resolve_all, ip)
            return result, None
        except Exception as exc:
            logger.error(f"Erreur DNS : {exc}")
            return result, self._make_error("DNS", str(exc))

    def _resolve_all(self, ip: str) -> ReverseDNSResult:
        """Effectue toutes les résolutions DNS (synchrone, exécuté dans un thread)."""
        result = ReverseDNSResult(ip=ip)

        # --- 1. Reverse DNS (PTR) ---
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                ptr_value = str(rdata).rstrip(".")
                result.ptr_record = ptr_value
                if ptr_value not in result.associated_domains:
                    result.associated_domains.append(ptr_value)
                result.dns_records.append(
                    DNSRecord(
                        record_type="PTR",
                        name=str(rev_name),
                        value=ptr_value,
                        ttl=answers.rrset.ttl if answers.rrset else 0,
                    )
                )
            logger.info(f"  PTR -> {result.ptr_record}")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ) as exc:
            logger.info(f"  Pas d'enregistrement PTR pour {ip} ({type(exc).__name__})")
        except Exception as exc:
            logger.warning(f"  Erreur PTR : {exc}")

        # --- 2. Résolution standard via socket (gethostbyaddr) ---
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            if hostname and hostname not in result.associated_domains:
                result.associated_domains.append(hostname)
            for alias in aliases:
                if alias not in result.associated_domains:
                    result.associated_domains.append(alias)
        except socket.herror:
            pass  # Pas de résolution inverse

        # --- 3. Pour chaque domaine trouvé, on récupère ses enregistrements ---
        for domain in list(result.associated_domains):
            self._resolve_domain_records(domain, result)

        logger.info(
            f"✓ DNS terminé - PTR: {result.ptr_record or 'N/A'}, "
            f"Domaines associés: {len(result.associated_domains)}"
        )
        return result

    def _resolve_domain_records(self, domain: str, result: ReverseDNSResult):
        """Résout les enregistrements A, AAAA, MX, NS, TXT, SOA d'un domaine."""
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
            try:
                answers = self.resolver.resolve(domain, rtype)
                for rdata in answers:
                    result.dns_records.append(
                        DNSRecord(
                            record_type=rtype,
                            name=domain,
                            value=str(rdata).rstrip("."),
                            ttl=answers.rrset.ttl if answers.rrset else 0,
                        )
                    )
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.resolver.Timeout,
            ):
                pass
            except Exception:
                pass
