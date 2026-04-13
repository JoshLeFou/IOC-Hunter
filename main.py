#!/usr/bin/env python3
"""
IOC-Hunter - Outil d'investigation technique sur adresses IP.

Interroge simultanément 6 sources de renseignement pour répondre aux
questions :

1. À qui appartient cette IP ?          -> WHOIS (RIR) + IPInfo
2. Où est-elle géolocalisée ?           -> IPInfo + WHOIS
3. Serveur dédié ou mutualisé ?         -> pDNS (VirusTotal)
4. Quel ASN / contexte réseau ?         -> WHOIS + IPInfo
5. Quels domaines associés ?            -> Reverse DNS + pDNS VT
6. Quels ports / services / headers ?   -> Shodan
7. Certificats SSL / JARM ?             -> Shodan + VT
8. Réputation / signalements ?          -> VirusTotal + AbuseIPDB
9. Fichiers malveillants communicants ?  -> VirusTotal

Usage :
    python main.py                          # Mode interactif
    python main.py 8.8.8.8                  # Analyse directe
    python main.py 8.8.8.8 --json           # Export JSON uniquement
    python main.py 8.8.8.8 --no-shodan      # Désactiver Shodan
"""

import argparse
import asyncio
import logging
import sys
from datetime import datetime

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from analyzers import (
    AbuseIPDBAnalyzer,
    DNSAnalyzer,
    IPInfoAnalyzer,
    ShodanAnalyzer,
    VirusTotalAnalyzer,
    WhoisAnalyzer,
)
from config import API_KEYS
from models import InvestigationReport
from report import display_report, enrich_report, export_json, export_markdown
from utils.ioc_parser import identify_ioc_type, is_ip_type

logger = logging.getLogger("main")
console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IOC-Hunter - Investigation technique sur adresses IP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("ip", nargs="?", help="Adresse IP à investiguer")
    parser.add_argument("--json", action="store_true", help="Exporter en JSON")
    parser.add_argument(
        "--markdown", "--md", action="store_true", help="Exporter en Markdown"
    )
    parser.add_argument("--no-vt", action="store_true", help="Désactiver VirusTotal")
    parser.add_argument("--no-shodan", action="store_true", help="Désactiver Shodan")
    parser.add_argument(
        "--no-abuseipdb", action="store_true", help="Désactiver AbuseIPDB"
    )
    parser.add_argument("--no-ipinfo", action="store_true", help="Désactiver IPInfo")
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Mode silencieux (pas d'affichage console)",
    )
    return parser.parse_args()


async def run_investigation(ip: str, args: argparse.Namespace) -> InvestigationReport:
    """
    Lance toutes les analyses en parallèle et agrège les résultats.
    """
    report = InvestigationReport(target_ip=ip)

    # --- Initialisation des analyseurs ---
    analyzers = {}

    # Les analyseurs sans clé API tournent toujours
    analyzers["whois"] = WhoisAnalyzer()
    analyzers["dns"] = DNSAnalyzer()

    # Les analyseurs avec clé API : activés seulement si la clé existe
    if not args.no_vt:
        analyzers["virustotal"] = VirusTotalAnalyzer(API_KEYS["virustotal"])
    if not args.no_abuseipdb:
        analyzers["abuseipdb"] = AbuseIPDBAnalyzer(API_KEYS["abuseipdb"])
    if not args.no_shodan:
        analyzers["shodan"] = ShodanAnalyzer(API_KEYS["shodan"])
    if not args.no_ipinfo:
        analyzers["ipinfo"] = IPInfoAnalyzer(API_KEYS["ipinfo"])

    # --- Exécution parallèle avec indicateur de progression ---
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:

        async def run_analyzer(name: str, analyzer, task_id):
            """Wrapper pour exécuter un analyseur et capturer son résultat."""
            try:
                result, error = await analyzer.analyze(ip)
                if error:
                    report.errors.append(error)
                return name, result
            except Exception as exc:
                logger.error(f"Erreur inattendue dans {name} : {exc}")
                from models import AnalyzerError

                report.errors.append(
                    AnalyzerError(
                        source=name,
                        error_type="CRASH",
                        message=str(exc),
                    )
                )
                return name, None
            finally:
                progress.update(task_id, completed=True)

        # Créer les tâches de progression
        tasks = []
        for name, analyzer in analyzers.items():
            task_id = progress.add_task(f"Interrogation {analyzer.name}...", total=1)
            tasks.append(run_analyzer(name, analyzer, task_id))

        # Lancement simultané de toutes les requêtes
        results = await asyncio.gather(*tasks)

    # --- Dispatch des résultats dans le rapport ---
    for name, result in results:
        if result is None:
            continue
        if name == "whois":
            report.whois = result
        elif name == "dns":
            report.reverse_dns = result
        elif name == "virustotal":
            report.virustotal = result
        elif name == "abuseipdb":
            report.abuseipdb = result
        elif name == "shodan":
            report.shodan = result
        elif name == "ipinfo":
            report.geolocation = result

    # --- Enrichissement (calcul des verdicts) ---
    report = enrich_report(report)

    return report


async def main():
    args = parse_args()

    # --- Récupération de l'IP cible ---
    if args.ip:
        ip_input = args.ip
    else:
        console.print(
            Panel(
                "[bold blue]IOC-Hunter[/bold blue]\n"
                "Outil d'investigation technique sur adresses IP\n"
                "Interroge : WHOIS · DNS · VirusTotal · AbuseIPDB · Shodan · IPInfo",
                border_style="blue",
            )
        )
        ip_input = console.input(
            "\n[bold]Entrez une adresse IP à investiguer :[/bold] "
        ).strip()

    # --- Validation ---
    clean_ioc, ioc_type = identify_ioc_type(ip_input)
    if not is_ip_type(ioc_type):
        console.print(
            f"[bold red]Erreur :[/bold red] '{ip_input}' n'est pas une adresse IP valide."
        )
        console.print("Cet outil est spécialisé dans l'investigation IP.")
        console.print(f"Type détecté : {ioc_type}")
        sys.exit(1)

    # --- Affichage des sources configurées ---
    console.print()
    console.print(f"[bold]Cible :[/bold] {clean_ioc} ({ioc_type})")
    configured = [name for name, key in API_KEYS.items() if key]
    always_on = ["whois", "dns"]
    all_sources = always_on + configured
    disabled = []
    if args.no_vt:
        disabled.append("virustotal")
    if args.no_shodan:
        disabled.append("shodan")
    if args.no_abuseipdb:
        disabled.append("abuseipdb")
    if args.no_ipinfo:
        disabled.append("ipinfo")

    active = [s for s in all_sources if s not in disabled]
    missing = [
        name for name, key in API_KEYS.items() if not key and name not in disabled
    ]

    console.print(f"[bold green]Sources actives :[/bold green] {', '.join(active)}")
    if missing:
        console.print(
            f"[bold yellow]Sans clé API :[/bold yellow] {', '.join(missing)} (seront ignorées)"
        )
    if disabled:
        console.print(f"[dim]Désactivées :[/dim] {', '.join(disabled)}")
    console.print()

    # --- Lancement de l'investigation ---
    logger.info(f"Début de l'investigation sur {clean_ioc}")
    report = await run_investigation(clean_ioc, args)
    logger.info("Investigation terminée")

    # --- Affichage ---
    if not args.quiet:
        display_report(report)

    # --- Exports ---
    json_path = export_json(report)
    console.print(f"[dim]📁 JSON -> {json_path}[/dim]")

    if args.markdown:
        md_path = export_markdown(report)
        console.print(f"[dim]📁 Markdown -> {md_path}[/dim]")

    return report


if __name__ == "__main__":
    asyncio.run(main())
