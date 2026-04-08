import httpx
import os

# Récupération de la clé API depuis les variables d'environnement (ou en dur pour tester)
VT_API_KEY = os.environ.get("VT_API_KEY", "VOTRE_CLE_API_ICI")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

async def analyze_with_vt(ioc: str, ioc_type: str) -> dict:
    """
    Interroge l'API v3 de VirusTotal de manière asynchrone.
    """
    if not VT_API_KEY or VT_API_KEY == "VOTRE_CLE_API_ICI":
        return {"source": "VirusTotal", "error": "Clé API manquante"}

    # Routage vers le bon point de terminaison de l'API selon le type d'IoC
    if ioc_type == "ip":
        endpoint = f"/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        endpoint = f"/domains/{ioc}"
    elif ioc_type == "hash":
        endpoint = f"/files/{ioc}"
    else:
        return {"source": "VirusTotal", "error": "Type d'IoC non supporté par VT"}

    url = f"{BASE_URL}{endpoint}"

    # Utilisation d'un client asynchrone httpx
    async with httpx.AsyncClient() as client:
        try:
            # On lance la requête GET
            response = await client.get(url, headers=HEADERS, timeout=10.0)
            
            # Gestion du quota dépassé (Code 429) ou non trouvé (Code 404)
            if response.status_code == 404:
                return {"source": "VirusTotal", "status": "Non trouvé (Inconnu de VT)"}
            elif response.status_code == 429:
                return {"source": "VirusTotal", "error": "Quota API dépassé"}
            
            response.raise_for_status() # Lève une erreur pour les autres codes HTTP (500, 401...)
            
            data = response.json()
            
            # Extraction des données utiles (les statistiques de détection)
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            return {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "link": f"https://www.virustotal.com/gui/{ioc_type}/{ioc}"
            }
            
        except httpx.RequestError as exc:
            return {"source": "VirusTotal", "error": f"Erreur de connexion: {str(exc)}"}