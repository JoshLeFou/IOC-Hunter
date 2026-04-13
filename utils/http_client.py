"""
Client HTTP partagé avec retry exponentiel, logging et gestion d'erreurs.
Toutes les requêtes API passent par ce client pour garantir
la robustesse et la traçabilité.
"""

import asyncio
import logging
from typing import Optional

import httpx

from config import HTTP_TIMEOUT, MAX_RETRIES, RETRY_BACKOFF

logger = logging.getLogger("http_client")


async def fetch_json(
    url: str,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout: float = HTTP_TIMEOUT,
    max_retries: int = MAX_RETRIES,
    source_name: str = "API",
) -> tuple[Optional[dict], Optional[str]]:
    """
    Effectue une requête GET avec retry exponentiel.

    Returns:
        Tuple (data_dict, error_string).
        Si succès : (data, None)
        Si erreur : (None, message_erreur)
    """
    last_error = ""

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(
                f"[{source_name}] Requête GET -> {url} (tentative {attempt}/{max_retries})"
            )

            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                verify=True,
            ) as client:
                response = await client.get(url, headers=headers, params=params)

            # --- Gestion des codes HTTP spécifiques ---
            if response.status_code == 200:
                data = response.json()
                logger.info(f"[{source_name}] ✓ Réponse 200 OK")
                return data, None

            elif response.status_code == 404:
                logger.warning(f"[{source_name}] 404 - Ressource non trouvée")
                return None, "Ressource non trouvée (404)"

            elif response.status_code == 401:
                logger.error(f"[{source_name}] 401 - Clé API invalide ou manquante")
                return None, "Clé API invalide ou manquante (401)"

            elif response.status_code == 403:
                logger.error(
                    f"[{source_name}] 403 - Accès interdit (vérifier les permissions de la clé)"
                )
                return None, "Accès interdit (403)"

            elif response.status_code == 429:
                wait = RETRY_BACKOFF**attempt
                logger.warning(
                    f"[{source_name}] 429 - Rate limit atteint, attente {wait:.1f}s..."
                )
                await asyncio.sleep(wait)
                last_error = "Quota API dépassé (429)"
                continue

            elif response.status_code >= 500:
                wait = RETRY_BACKOFF**attempt
                logger.warning(
                    f"[{source_name}] {response.status_code} - Erreur serveur, retry dans {wait:.1f}s"
                )
                await asyncio.sleep(wait)
                last_error = f"Erreur serveur ({response.status_code})"
                continue

            else:
                last_error = f"Code HTTP inattendu : {response.status_code}"
                logger.warning(f"[{source_name}] {last_error}")
                return None, last_error

        except httpx.TimeoutException:
            wait = RETRY_BACKOFF**attempt
            last_error = f"Timeout après {timeout}s"
            logger.warning(f"[{source_name}] {last_error}, retry dans {wait:.1f}s")
            await asyncio.sleep(wait)

        except httpx.RequestError as exc:
            last_error = f"Erreur de connexion : {exc}"
            logger.error(f"[{source_name}] {last_error}")
            return None, last_error

        except Exception as exc:
            last_error = f"Erreur inattendue : {exc}"
            logger.error(f"[{source_name}] {last_error}")
            return None, last_error

    return None, f"Échec après {max_retries} tentatives - {last_error}"
