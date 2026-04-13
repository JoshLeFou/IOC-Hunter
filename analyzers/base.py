"""
Classe de base abstraite pour tous les analyseurs.
Garantit une interface uniforme et gère les erreurs de manière cohérente.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from models import AnalyzerError


class BaseAnalyzer(ABC):
    """Interface commune à tous les analyseurs CTI."""

    name: str = "BaseAnalyzer"
    requires_api_key: bool = True

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.logger = logging.getLogger(self.name)

    @property
    def is_configured(self) -> bool:
        """Vérifie si l'analyseur dispose de sa clé API (si requise)."""
        if not self.requires_api_key:
            return True
        return bool(self.api_key)

    @abstractmethod
    async def analyze(self, ip: str) -> tuple[Optional[Any], Optional[AnalyzerError]]:
        """
        Lance l'analyse sur une IP.

        Returns:
            Tuple (résultat typé, erreur optionnelle).
        """
        ...

    def _make_error(self, error_type: str, message: str) -> AnalyzerError:
        """Crée un objet erreur standardisé."""
        return AnalyzerError(
            source=self.name,
            error_type=error_type,
            message=message,
        )
