import re

def identify_ioc_type(ioc: str) -> str:
    """
    Analyse l'entrée utilisateur et retourne le type d'IoC.
    """
    # Pattern pour une adresse IPv4
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
        return "ip"
        
    # Pattern pour les Hashes (MD5 = 32, SHA1 = 40, SHA256 = 64 caractères)
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
        return "hash"
        
    # Pattern simplifié pour un Nom de Domaine
    if re.match(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", ioc.lower()):
        return "domain"
        
    return "unknown"