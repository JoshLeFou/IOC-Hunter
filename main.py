import asyncio
from utils.ioc_parser import identify_ioc_type

# --- Simulation de nos futurs "Analyzers" ---

async def fetch_virustotal(ioc: str, ioc_type: str):
    """Simule une requête vers l'API VirusTotal (Accepte IP, Domaine, Hash)"""
    print(f"[+] Lancement de l'analyse VirusTotal pour {ioc}...")
    await asyncio.sleep(1.5) # Simule l'attente du réseau
    return {"source": "VirusTotal", "status": "clean", "malicious_votes": 0}

async def fetch_abuseipdb(ioc: str, ioc_type: str):
    """Simule une requête vers AbuseIPDB (N'accepte QUE les IP)"""
    if ioc_type != "ip":
        return None # On ignore silencieusement si ce n'est pas une IP
        
    print(f"[+] Lancement de l'analyse AbuseIPDB pour {ioc}...")
    await asyncio.sleep(1) # Simule l'attente du réseau
    return {"source": "AbuseIPDB", "confidence_score": 15, "total_reports": 2}


# --- Cœur du programme ---

async def main():
    # 1. Récupération de l'entrée utilisateur
    ioc_input = input("Entrez un IoC (IP, Domaine, Hash) : ").strip()
    
    # 2. Identification du type
    ioc_type = identify_ioc_type(ioc_input)
    if ioc_type == "unknown":
        print("[-] Erreur : Type d'IoC non reconnu. Veuillez vérifier votre saisie.")
        return

    print(f"[*] Type détecté : {ioc_type.upper()}")
    print("[*] Interrogation des sources en parallèle...\n")

    # 3. Préparation des requêtes asynchrones
    # On prépare la liste de tous les modules à lancer en même temps
    tasks = [
        fetch_virustotal(ioc_input, ioc_type),
        fetch_abuseipdb(ioc_input, ioc_type)
    ]

    # 4. Exécution simultanée de toutes les requêtes
    results = await asyncio.gather(*tasks)

    # 5. Nettoyage des résultats (on retire les "None" des API qui n'étaient pas concernées)
    valid_results = [res for res in results if res is not None]

    # 6. Affichage basique (pour le moment)
    print("\n--- RÉSULTATS AGRÉGÉS ---")
    for res in valid_results:
        print(res)

if __name__ == "__main__":
    # Lancement de la boucle asynchrone
    asyncio.run(main())