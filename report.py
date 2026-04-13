"""
Générateur de rapports d'investigation CTI.

Produit :
1. Un affichage console structuré et lisible (via Rich)
2. Un export JSON brut pour traitement automatisé
3. Un export Markdown pour documentation
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import KNOWN_HOSTING_PROVIDERS, REPORTS_DIR
from models import InvestigationReport, ServerType, Severity

logger = logging.getLogger("Report")
console = Console()


# =============================================================================
# MOTEUR D'AGRÉGATION - Calcul du verdict final
# =============================================================================


def compute_severity(report: InvestigationReport) -> Severity:
    """Calcule la sévérité globale en croisant toutes les sources."""
    scores = []

    # VT : détection malveillante
    if report.virustotal:
        vt = report.virustotal
        mal = vt.stats.malicious
        if mal >= 10:
            scores.append(4)  # CRITICAL
        elif mal >= 5:
            scores.append(3)  # HIGH
        elif mal >= 1:
            scores.append(2)  # MEDIUM
        else:
            scores.append(0)

        # Fichiers communicants malveillants -> augmente la sévérité
        if any(f.get("malicious", 0) > 5 for f in vt.communicating_files):
            scores.append(3)

    # AbuseIPDB : score de confiance
    if report.abuseipdb:
        conf = report.abuseipdb.abuse_confidence_score
        if conf >= 80:
            scores.append(4)
        elif conf >= 50:
            scores.append(3)
        elif conf >= 20:
            scores.append(2)
        elif conf > 0:
            scores.append(1)

    # Shodan : CVEs connues
    if report.shodan and report.shodan.vulns:
        scores.append(min(3, len(report.shodan.vulns)))

    if not scores:
        return Severity.UNKNOWN

    max_score = max(scores)
    return {
        4: Severity.CRITICAL,
        3: Severity.HIGH,
        2: Severity.MEDIUM,
        1: Severity.LOW,
        0: Severity.CLEAN,
    }.get(max_score, Severity.UNKNOWN)


def compute_server_type(report: InvestigationReport) -> ServerType:
    """
    Détermine le type de serveur
    Utilise le pDNS VT pour compter les domaines co-résolvant.
    """
    if report.virustotal and report.virustotal.passive_dns:
        count = len(report.virustotal.passive_dns)
        if count > 50:
            return ServerType.SHARED  # ou CDN ou parking
        elif count <= 5:
            return ServerType.DEDICATED

    return ServerType.UNKNOWN


def enrich_report(report: InvestigationReport) -> InvestigationReport:
    """Enrichit le rapport avec les verdicts calculés."""
    report.severity = compute_severity(report)
    report.server_type = compute_server_type(report)
    report.investigation_end = datetime.now().isoformat()

    # Notes de confiance
    if report.whois and report.geolocation:
        report.confidence_notes.append(
            "WHOIS et géolocalisation disponibles - confiance élevée sur l'attribution"
        )
    if report.virustotal and report.virustotal.passive_dns:
        count = len(report.virustotal.passive_dns)
        report.confidence_notes.append(f"pDNS VT : {count} résolution(s) historique(s)")
    if not report.shodan:
        report.confidence_notes.append("Shodan indisponible - profiling serveur limité")

    return report


# =============================================================================
# AFFICHAGE CONSOLE (Rich)
# =============================================================================

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.CLEAN: "bold green",
    Severity.UNKNOWN: "bold dim",
}


def display_report(report: InvestigationReport):
    """Affiche le rapport complet dans la console avec Rich."""

    # --- Header ---
    sev = report.severity
    sev_style = SEVERITY_COLORS.get(sev, "")
    header = Text()
    header.append(
        f"  RAPPORT D'INVESTIGATION - {report.target_ip}  ", style="bold white on blue"
    )
    console.print()
    console.print(header, justify="center")
    console.print()

    verdict_text = Text(f"  VERDICT : {sev.value}  ", style=sev_style)
    console.print(verdict_text, justify="center")
    console.print(f"  Type de serveur : {report.server_type.value}", justify="center")
    console.print()

    # --- 1. WHOIS ---
    if report.whois:
        w = report.whois
        table = Table(
            title="  WHOIS IP (Registre RIR)", box=box.ROUNDED, title_style="bold cyan"
        )
        table.add_column("Propriété", style="bold", width=22)
        table.add_column("Valeur")
        table.add_row("Organisation", w.organization)
        table.add_row("Réseau", f"{w.network_name} ({w.network_range})")
        table.add_row("ASN", f"AS{w.asn} - {w.asn_description}")
        table.add_row("Pays", w.country)
        table.add_row("Contact abus", w.abuse_contact or "N/A")
        table.add_row("Date d'allocation", w.registration_date or "N/A")
        console.print(table)
        console.print()

    # --- 2. Géolocalisation ---
    if report.geolocation:
        g = report.geolocation
        table = Table(
            title="  Géolocalisation", box=box.ROUNDED, title_style="bold cyan"
        )
        table.add_column("Propriété", style="bold", width=22)
        table.add_column("Valeur")
        table.add_row("Ville", g.city)
        table.add_row("Région", g.region)
        table.add_row("Pays", f"{g.country} ({g.country_code})")
        table.add_row("Coordonnées", f"{g.latitude}, {g.longitude}")
        table.add_row("Fuseau", g.timezone)
        table.add_row("ISP / Org", g.isp)
        table.add_row("ASN", f"AS{g.as_number} - {g.as_name}")
        console.print(table)
        console.print()

    # --- 3. Reverse DNS ---
    if report.reverse_dns:
        dns_r = report.reverse_dns
        table = Table(
            title="  DNS (Reverse + Résolutions)",
            box=box.ROUNDED,
            title_style="bold cyan",
        )
        table.add_column("Type", style="bold", width=8)
        table.add_column("Nom", width=35)
        table.add_column("Valeur")
        table.add_column("TTL", width=8)

        if dns_r.ptr_record:
            table.add_row("PTR", dns_r.ip, dns_r.ptr_record, "")

        for rec in dns_r.dns_records[:20]:  # Limiter l'affichage
            table.add_row(rec.record_type, rec.name, rec.value, str(rec.ttl))

        console.print(table)
        if dns_r.associated_domains:
            console.print(
                f"  Domaines associés : {', '.join(dns_r.associated_domains[:10])}"
            )
        console.print()

    # --- 4. VirusTotal ---
    if report.virustotal:
        vt = report.virustotal
        mal_style = "bold red" if vt.stats.malicious > 0 else "green"

        table = Table(title="  VirusTotal", box=box.ROUNDED, title_style="bold cyan")
        table.add_column("Propriété", style="bold", width=22)
        table.add_column("Valeur")
        table.add_row("Détection", Text(f"{vt.stats.detection_ratio}", style=mal_style))
        table.add_row("Réputation", str(vt.reputation))
        table.add_row("AS Owner", vt.as_owner)
        table.add_row("Pays", vt.country)
        table.add_row("Lien", vt.link)
        console.print(table)

        # Passive DNS
        if vt.passive_dns:
            pdns_table = Table(title="  ↳ DNS Passif (VT)", box=box.SIMPLE)
            pdns_table.add_column("Domaine", width=40)
            pdns_table.add_column("Date de résolution")
            for entry in vt.passive_dns[:15]:
                date_val = entry.get("date", "")
                if isinstance(date_val, int) and date_val > 0:
                    from datetime import datetime as dt

                    date_val = dt.fromtimestamp(date_val).strftime("%Y-%m-%d")
                pdns_table.add_row(entry.get("hostname", ""), str(date_val))
            console.print(pdns_table)

        # Fichiers communicants
        if vt.communicating_files:
            files_table = Table(title="  ↳ Fichiers communicants", box=box.SIMPLE)
            files_table.add_column("Nom", width=30)
            files_table.add_column("Type", width=15)
            files_table.add_column("Détections", width=12)
            files_table.add_column("SHA256", width=20)
            for f in vt.communicating_files[:10]:
                det = f"{f.get('malicious', 0)}/{f.get('total', 0)}"
                sha = f.get("sha256", "")[:16] + "…" if f.get("sha256") else ""
                files_table.add_row(
                    f.get("name", "N/A"),
                    f.get("type", ""),
                    det,
                    sha,
                )
            console.print(files_table)
        console.print()

    # --- 5. AbuseIPDB ---
    if report.abuseipdb:
        a = report.abuseipdb
        score_style = (
            "bold red"
            if a.abuse_confidence_score >= 50
            else "bold yellow"
            if a.abuse_confidence_score >= 20
            else "green"
        )

        table = Table(title="  AbuseIPDB", box=box.ROUNDED, title_style="bold cyan")
        table.add_column("Propriété", style="bold", width=22)
        table.add_column("Valeur")
        table.add_row(
            "Score de confiance",
            Text(f"{a.abuse_confidence_score}%", style=score_style),
        )
        table.add_row(
            "Signalements",
            f"{a.total_reports} (par {a.num_distinct_users} utilisateurs)",
        )
        table.add_row("Dernier signalement", a.last_reported_at or "Aucun")
        table.add_row("ISP", a.isp)
        table.add_row("Type d'usage", a.usage_type)
        table.add_row("Pays", a.country_code)
        if a.categories:
            table.add_row("Catégories d'abus", ", ".join(a.categories))
        console.print(table)
        console.print()

    # --- 6. Shodan ---
    if report.shodan:
        s = report.shodan
        table = Table(
            title="  Shodan (Profiling serveur)",
            box=box.ROUNDED,
            title_style="bold cyan",
        )
        table.add_column("Propriété", style="bold", width=22)
        table.add_column("Valeur")
        table.add_row("Hostnames", ", ".join(s.hostnames) if s.hostnames else "N/A")
        table.add_row("OS détecté", s.os or "N/A")
        table.add_row("Dernière MAJ", s.last_update)

        if s.vulns:
            vuln_text = Text(", ".join(s.vulns[:10]), style="bold red")
            table.add_row("CVEs", vuln_text)

        console.print(table)

        # Ports ouverts
        if s.ports:
            ports_table = Table(title="  ↳ Ports ouverts", box=box.SIMPLE)
            ports_table.add_column("Port", width=8)
            ports_table.add_column("Proto", width=6)
            ports_table.add_column("Service", width=15)
            ports_table.add_column("Produit", width=20)
            ports_table.add_column("Version", width=12)
            for p in s.ports:
                ports_table.add_row(
                    str(p.port), p.protocol, p.service, p.product, p.version
                )
            console.print(ports_table)

        # Certificats SSL
        if s.certificates:
            cert_table = Table(title="  ↳ Certificats SSL", box=box.SIMPLE)
            cert_table.add_column("Subject CN", width=30)
            cert_table.add_column("Issuer", width=25)
            cert_table.add_column("Validité")
            cert_table.add_column("JARM", width=20)
            for c in s.certificates:
                jarm_display = (c.jarm[:16] + "…") if c.jarm else "N/A"
                cert_table.add_row(
                    c.subject,
                    c.issuer,
                    f"{c.valid_from} -> {c.valid_to}",
                    jarm_display,
                )
            console.print(cert_table)
        console.print()

    # --- Erreurs ---
    if report.errors:
        err_table = Table(
            title="  Erreurs rencontrées", box=box.ROUNDED, title_style="bold yellow"
        )
        err_table.add_column("Source", style="bold", width=15)
        err_table.add_column("Type", width=12)
        err_table.add_column("Message")
        for e in report.errors:
            err_table.add_row(e.source, e.error_type, e.message)
        console.print(err_table)
        console.print()

    # --- Notes de confiance ---
    if report.confidence_notes:
        notes = Panel(
            "\n".join(f"  • {n}" for n in report.confidence_notes),
            title="  Notes de confiance",
            border_style="dim",
        )
        console.print(notes)
        console.print()


# =============================================================================
# EXPORTS
# =============================================================================


def export_json(report: InvestigationReport) -> Path:
    """Exporte le rapport en JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = REPORTS_DIR / f"report_{report.target_ip.replace('.', '_')}_{ts}.json"
    filepath.write_text(report.to_json(), encoding="utf-8")
    logger.info(f"Rapport JSON exporté -> {filepath}")
    return filepath


def export_markdown(report: InvestigationReport) -> Path:
    """Exporte le rapport en Markdown."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = REPORTS_DIR / f"report_{report.target_ip.replace('.', '_')}_{ts}.md"

    lines = [
        f"# Rapport d'investigation CTI - {report.target_ip}",
        f"",
        f"**Date** : {report.investigation_start}",
        f"**Verdict** : {report.severity.value}",
        f"**Type de serveur** : {report.server_type.value}",
        f"",
    ]

    if report.whois:
        w = report.whois
        lines += [
            "## WHOIS IP",
            f"- **Organisation** : {w.organization}",
            f"- **Réseau** : {w.network_name} ({w.network_range})",
            f"- **ASN** : AS{w.asn} - {w.asn_description}",
            f"- **Pays** : {w.country}",
            f"- **Contact abus** : {w.abuse_contact or 'N/A'}",
            "",
        ]

    if report.geolocation:
        g = report.geolocation
        lines += [
            "## Géolocalisation",
            f"- **Ville** : {g.city}, {g.region}, {g.country}",
            f"- **Coordonnées** : {g.latitude}, {g.longitude}",
            f"- **ISP** : {g.isp}",
            f"- **ASN** : AS{g.as_number}",
            "",
        ]

    if report.virustotal:
        vt = report.virustotal
        lines += [
            "## VirusTotal",
            f"- **Détection** : {vt.stats.detection_ratio}",
            f"- **Réputation** : {vt.reputation}",
            f"- **DNS Passif** : {len(vt.passive_dns)} résolution(s)",
            f"- **Fichiers communicants** : {len(vt.communicating_files)}",
            f"- [Lien VT]({vt.link})",
            "",
        ]

    if report.abuseipdb:
        a = report.abuseipdb
        lines += [
            "## AbuseIPDB",
            f"- **Score** : {a.abuse_confidence_score}%",
            f"- **Signalements** : {a.total_reports}",
            f"- **Type d'usage** : {a.usage_type}",
            f"- **Catégories** : {', '.join(a.categories) if a.categories else 'N/A'}",
            "",
        ]

    if report.shodan:
        s = report.shodan
        lines += [
            "## Shodan",
            f"- **Ports** : {', '.join(str(p.port) for p in s.ports)}",
            f"- **OS** : {s.os or 'N/A'}",
            f"- **CVEs** : {', '.join(s.vulns) if s.vulns else 'Aucune'}",
            "",
        ]

    if report.errors:
        lines += [
            "## Erreurs",
            *[f"- **{e.source}** : {e.message}" for e in report.errors],
            "",
        ]

    if report.confidence_notes:
        lines += [
            "## Notes de confiance",
            *[f"- {n}" for n in report.confidence_notes],
            "",
        ]

    filepath.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Rapport Markdown exporté -> {filepath}")
    return filepath
