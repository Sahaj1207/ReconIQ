"""
ReconIQ Evidence Collector Facade

Purpose:
Primary orchestrator in the Ingestion layer responsible for collecting artifacts from user input.
The EvidenceCollector delegates extraction tasks to pluggable sub-components (e.g., IOCExtractor).

Responsibilities:
- Ingest an IngestedInput payload object
- Dispatch payload to all registered extractors matching the input's source type
- Merge, deduplicate, and sort extracted evidence artifacts deterministically
- Provide structured logging and execution performance telemetry
- Ensure robust fault tolerance so individual extractor failures do not crash the investigation

Future Implementation Notes:
- Dynamic discovery of third-party extractor plugins.
- Asynchronous parallel execution of extractors using asyncio.gather.
"""

import time
import logging
from typing import List, Dict, Set, Union, Optional

from app.ingestion.ingested_input import IngestedInput, IngestionSourceType
from app.ingestion.extractors.base import BaseExtractor
from app.ingestion.extractors.ioc_extractor import IOCExtractor
from app.schemas.evidence import EvidenceCollectionResponse
from app.schemas.ioc import IOCResults, IOCSummary

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """
    Central Evidence Collector facade orchestrating pluggable artifact extractors.
    """

    def __init__(self, extractors: Optional[List[BaseExtractor]] = None) -> None:
        """
        Initializes the EvidenceCollector facade with registered extractors.

        Args:
            extractors (Optional[List[BaseExtractor]]): Initial list of extractors.
                Defaults to registering IOCExtractor.
        """
        self._extractors: List[BaseExtractor] = []

        if extractors:
            for extractor in extractors:
                self.register_extractor(extractor)
        else:
            # Default registration: IOCExtractor
            self.register_extractor(IOCExtractor())

    def register_extractor(self, extractor: BaseExtractor) -> None:
        """
        Registers a new artifact extractor sub-component into the collector.

        Args:
            extractor (BaseExtractor): Instance of a BaseExtractor implementation.
        """
        if not isinstance(extractor, BaseExtractor):
            raise TypeError("Extractor must implement BaseExtractor interface.")

        self._extractors.append(extractor)
        logger.info(f"Registered evidence extractor plugin: [{extractor.name}]")

    def collect(
        self,
        input_payload: Union[IngestedInput, str],
        refang: bool = True
    ) -> EvidenceCollectionResponse:
        """
        Orchestrates evidence extraction across all registered extractors matching the input source type.

        Args:
            input_payload (Union[IngestedInput, str]): Input payload object or raw text string.
            refang (bool): Refang defanged indicators if True (used when input_payload is str).

        Returns:
            EvidenceCollectionResponse: Structured extraction result containing summary counts and results.
        """
        start_time = time.perf_counter()

        # Standardize string input to IngestedInput model
        if isinstance(input_payload, str):
            input_data = IngestedInput.from_text(
                text=input_payload,
                metadata={"refang": refang}
            )
        else:
            input_data = input_payload
            if refang and "refang" not in input_data.metadata:
                input_data.metadata["refang"] = refang

        content_length = len(input_data.content) if input_data.content else 0
        logger.info(
            f"Starting evidence collection | Source: [{input_data.source_type}] | "
            f"Length: {content_length} chars | Registered Extractors: {len(self._extractors)}"
        )

        # Categorized result accumulators
        merged_ipv4: Set[str] = set()
        merged_ipv6: Set[str] = set()
        merged_urls: Set[str] = set()
        merged_domains: Set[str] = set()
        merged_emails: Set[str] = set()
        merged_phone_numbers: Set[str] = set()
        merged_hashes: Set[str] = set()

        # Dispatch input_data to each matching registered extractor
        for extractor in self._extractors:
            if input_data.source_type not in extractor.supported_source_types:
                logger.debug(
                    f"Skipping extractor [{extractor.name}] - source type [{input_data.source_type}] not supported."
                )
                continue

            try:
                ext_start = time.perf_counter()
                extracted_data = extractor.extract(input_data)
                ext_duration = round((time.perf_counter() - ext_start) * 1000, 2)

                # Merge extracted category sets safely
                merged_ipv4.update(extracted_data.get("ipv4", []))
                merged_ipv6.update(extracted_data.get("ipv6", []))
                merged_urls.update(extracted_data.get("urls", []))
                merged_domains.update(extracted_data.get("domains", []))
                merged_emails.update(extracted_data.get("emails", []))
                merged_phone_numbers.update(extracted_data.get("phone_numbers", []))
                merged_hashes.update(extracted_data.get("hashes", []))

                logger.debug(
                    f"Extractor [{extractor.name}] finished in {ext_duration}ms"
                )
            except Exception as exc:
                # Failure boundary: Log warning without crashing investigation pipeline
                logger.error(
                    f"Extractor [{extractor.name}] failed during execution: {exc}",
                    exc_info=True
                )

        # Build final deterministic Pydantic DTOs
        results = IOCResults(
            ipv4=sorted(list(merged_ipv4)),
            ipv6=sorted(list(merged_ipv6)),
            urls=sorted(list(merged_urls)),
            domains=sorted(list(merged_domains)),
            emails=sorted(list(merged_emails)),
            phone_numbers=sorted(list(merged_phone_numbers)),
            hashes=sorted(list(merged_hashes)),
        )

        total_iocs = (
            len(results.ipv4) +
            len(results.ipv6) +
            len(results.urls) +
            len(results.domains) +
            len(results.emails) +
            len(results.phone_numbers) +
            len(results.hashes)
        )

        summary = IOCSummary(
            total_iocs=total_iocs,
            ipv4_count=len(results.ipv4),
            ipv6_count=len(results.ipv6),
            url_count=len(results.urls),
            domain_count=len(results.domains),
            email_count=len(results.emails),
            phone_count=len(results.phone_numbers),
            hash_count=len(results.hashes),
        )

        execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        logger.info(
            f"Evidence collection completed | Total IOCs: {total_iocs} "
            f"(IPv4: {summary.ipv4_count}, IPv6: {summary.ipv6_count}, URLs: {summary.url_count}, "
            f"Domains: {summary.domain_count}, Emails: {summary.email_count}, Phones: {summary.phone_count}) | "
            f"Latency: {execution_time_ms}ms"
        )

        return EvidenceCollectionResponse(
            status="success",
            execution_time_ms=execution_time_ms,
            summary=summary,
            results=results,
        )
