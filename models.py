"""
Modèles de données structurés pour les résultats d'investigation CTI.
Chaque dataclass correspond à un type de résultat d'analyse.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Niveau de sévérité d'un IoC après analyse."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class ServerType(str, Enum):
    """Type de serveur identifié"""

    DEDICATED = "Serveur dédié"
    SHARED = "Serveur mutualisé"
    CDN = "CDN"
    SINKHOLE = "Sinkhole"
    PARKING = "Page de parking"
    UNKNOWN = "Indéterminé"


@dataclass
class WhoisInfo:
    """Informations WHOIS d'une adresse IP (registre RIR)."""

    ip: str = ""
    network_name: str = ""  # netname
    network_range: str = ""  # inetnum / CIDR
    description: str = ""  # descr
    country: str = ""
    organization: str = ""
    asn: int = 0
    asn_description: str = ""
    abuse_contact: str = ""
    registration_date: str = ""
    last_modified: str = ""


@dataclass
class GeoLocation:
    """Géolocalisation d'une adresse IP."""

    ip: str = ""
    city: str = ""
    region: str = ""
    country: str = ""
    country_code: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    isp: str = ""
    org: str = ""
    as_number: int = 0
    as_name: str = ""


@dataclass
class DNSRecord:
    """Un enregistrement DNS individuel."""

    record_type: str = ""  # A, AAAA, MX, NS, TXT, SOA, PTR...
    name: str = ""
    value: str = ""
    ttl: int = 0


@dataclass
class ReverseDNSResult:
    """Résultat du Reverse DNS + résolutions passives."""

    ip: str = ""
    ptr_record: str = ""
    associated_domains: list[str] = field(default_factory=list)
    dns_records: list[DNSRecord] = field(default_factory=list)


@dataclass
class PortInfo:
    """Information sur un port ouvert (Shodan)."""

    port: int = 0
    protocol: str = ""  # tcp/udp
    service: str = ""  # http, ssh, ftp...
    product: str = ""  # nginx, Apache, OpenSSH...
    version: str = ""
    banner: str = ""
    cpe: list[str] = field(default_factory=list)


@dataclass
class SSLCertificate:
    """Certificat SSL/TLS trouvé sur le serveur."""

    serial: str = ""
    issuer: str = ""
    subject: str = ""
    subject_alt_names: list[str] = field(default_factory=list)
    valid_from: str = ""
    valid_to: str = ""
    fingerprint_sha256: str = ""
    ja3s: str = ""
    jarm: str = ""


@dataclass
class ShodanResult:
    """Résultat complet d'une analyse Shodan."""

    ip: str = ""
    hostnames: list[str] = field(default_factory=list)
    os: str = ""
    ports: list[PortInfo] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    certificates: list[SSLCertificate] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    last_update: str = ""


@dataclass
class VTAnalysisStats:
    """Statistiques de détection VirusTotal."""

    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0

    @property
    def total(self) -> int:
        return (
            self.malicious
            + self.suspicious
            + self.undetected
            + self.harmless
            + self.timeout
        )

    @property
    def detection_ratio(self) -> str:
        if self.total == 0:
            return "N/A"
        return f"{self.malicious}/{self.total}"


@dataclass
class VTResult:
    """Résultat complet VirusTotal pour une IP."""

    ip: str = ""
    stats: VTAnalysisStats = field(default_factory=VTAnalysisStats)
    reputation: int = 0
    as_owner: str = ""
    country: str = ""
    passive_dns: list[dict] = field(default_factory=list)
    communicating_files: list[dict] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    link: str = ""


@dataclass
class AbuseIPDBResult:
    """Résultat AbuseIPDB."""

    ip: str = ""
    is_public: bool = True
    abuse_confidence_score: int = 0
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: str = ""
    isp: str = ""
    domain: str = ""
    country_code: str = ""
    usage_type: str = ""
    is_whitelisted: bool = False
    categories: list[str] = field(default_factory=list)


@dataclass
class AnalyzerError:
    """Erreur survenue lors d'une analyse."""

    source: str
    error_type: str
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class InvestigationReport:
    """
    Rapport complet d'investigation sur une adresse IP.
    Agrège tous les résultats de tous les analyseurs.
    """

    target_ip: str
    investigation_start: str = field(default_factory=lambda: datetime.now().isoformat())
    investigation_end: str = ""

    # Résultats par source
    whois: Optional[WhoisInfo] = None
    geolocation: Optional[GeoLocation] = None
    reverse_dns: Optional[ReverseDNSResult] = None
    shodan: Optional[ShodanResult] = None
    virustotal: Optional[VTResult] = None
    abuseipdb: Optional[AbuseIPDBResult] = None

    # Erreurs rencontrées
    errors: list[AnalyzerError] = field(default_factory=list)

    # Méta-analyse (rempli par le moteur d'agrégation)
    severity: Severity = Severity.UNKNOWN
    server_type: ServerType = ServerType.UNKNOWN
    confidence_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Sérialisation en dictionnaire (pour JSON/export)."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Sérialisation JSON propre."""
        return json.dumps(
            self.to_dict(), indent=indent, default=str, ensure_ascii=False
        )
