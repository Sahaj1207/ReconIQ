"""
ReconIQ Base Extractor Interface

Purpose:
Abstract base class contract for all ReconIQ evidence extractor components.

Responsibilities:
- Define standard async/sync extract() interface
- Specify supported ingestion source types for extractor execution
- Enforce strongly typed result schemas across pluggable extractors

Future Implementation Notes:
- Plugin registry mechanism to dynamically discover and register extractors.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from app.ingestion.ingested_input import IngestedInput, IngestionSourceType


class BaseExtractor(ABC):
    """
    Abstract Base Class for all ReconIQ Evidence Extractors.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique descriptive identifier for the extractor."""
        pass

    @property
    @abstractmethod
    def supported_source_types(self) -> List[IngestionSourceType]:
        """List of IngestionSourceType enums supported by this extractor."""
        pass

    @abstractmethod
    def extract(self, input_data: IngestedInput) -> Dict[str, Any]:
        """
        Executes artifact extraction on the provided IngestedInput object.

        Args:
            input_data (IngestedInput): Unified input payload object.

        Returns:
            Dict[str, Any]: Strongly typed dictionary of extracted artifacts.
        """
        pass
