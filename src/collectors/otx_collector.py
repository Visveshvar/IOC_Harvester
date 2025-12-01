"""
AlienVault OTX Collector
Fetches IOCs from AlienVault Open Threat Exchange
"""

import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from src.collectors.base_collector import BaseCollector
from src.models.ioc_model import IOCType, IOCRole

logger = logging.getLogger(__name__)


class OTXCollector(BaseCollector):
    """
    Collector for AlienVault OTX

    Fetches:
    - Pulses (threat collections)
    - Indicators within each pulse
    """

    # OTX API endpoints
    BASE_URL = "https://otx.alienvault.com/api/v1"
    PULSES_URL = f"{BASE_URL}/pulses/subscribed"
    PULSE_DETAILS_URL = f"{BASE_URL}/pulses"

    def __init__(self, api_key: str):
        """
        Initialize OTX collector

        Args:
            api_key: OTX API key
        """
        super().__init__(name="OTX", api_key=api_key)

        if not api_key:
            raise ValueError("OTX API key is required")

        self.headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"
        }

    async def fetch(self) -> List[Dict[str, Any]]:
        """
        Fetch IOCs from OTX

        Steps:
        1. Get list of subscribed pulses
        2. For each pulse, get indicators
        3. Return all indicators

        Returns:
            List of raw indicator dictionaries
        """
        all_indicators = []

        try:
            async with aiohttp.ClientSession() as session:
                # Step 1: Get subscribed pulses
                self.logger.info("Fetching subscribed pulses...")
                pulses = await self._get_subscribed_pulses(session)
                self.logger.info(f"Found {len(pulses)} subscribed pulses")

                # Step 2: Get indicators from each pulse
                for idx, pulse in enumerate(pulses):
                    try:
                        pulse_id = pulse.get("id")
                        pulse_name = pulse.get("name", "Unknown")

                        self.logger.info(f"  [{idx + 1}/{len(pulses)}] Processing pulse: {pulse_name}")

                        # Get indicators for this pulse
                        indicators = await self._get_pulse_indicators(session, pulse_id)

                        # Add pulse metadata to each indicator
                        for indicator in indicators:
                            indicator["pulse_id"] = pulse_id
                            indicator["pulse_name"] = pulse_name
                            indicator["pulse_created"] = pulse.get("created")
                            indicator["pulse_tags"] = pulse.get("tags", [])

                        all_indicators.extend(indicators)
                        self.logger.info(f"    ✓ Got {len(indicators)} indicators")

                        # Rate limiting - be nice to OTX API
                        await asyncio.sleep(0.5)

                    except Exception as e:
                        self.logger.error(f"    ✗ Error processing pulse {pulse_id}: {e}")
                        continue

        except Exception as e:
            self.logger.error(f"Error fetching from OTX: {e}")
            raise

        return all_indicators

    async def _get_subscribed_pulses(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Get list of subscribed pulses from OTX

        Args:
            session: aiohttp session

        Returns:
            List of pulse dictionaries
        """
        try:
            async with session.get(
                    self.PULSES_URL,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=30)
            ) as response:

                if response.status != 200:
                    raise Exception(f"OTX API returned status {response.status}")

                data = await response.json()

                # Extract pulses from response
                pulses = data.get("results", [])
                self.logger.debug(f"Got {len(pulses)} pulses from API")

                return pulses

        except Exception as e:
            self.logger.error(f"Error getting pulses: {e}")
            raise

    async def _get_pulse_indicators(self, session: aiohttp.ClientSession, pulse_id: str) -> List[Dict]:
        """
        Get indicators for a specific pulse

        Args:
            session: aiohttp session
            pulse_id: Pulse ID

        Returns:
            List of indicator dictionaries
        """
        try:
            url = f"{self.PULSE_DETAILS_URL}/{pulse_id}"

            async with session.get(
                    url,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=30)
            ) as response:

                if response.status != 200:
                    raise Exception(f"OTX API returned status {response.status}")

                data = await response.json()

                # Extract indicators
                indicators = data.get("indicators", [])
                self.logger.debug(f"Got {len(indicators)} indicators from pulse {pulse_id}")

                return indicators

        except Exception as e:
            self.logger.error(f"Error getting indicators for pulse {pulse_id}: {e}")
            return []

    def normalize(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize raw OTX indicators to standard IOC format

        Args:
            raw_data: Raw indicators from OTX

        Returns:
            List of normalized IOCs
        """
        normalized_iocs = []

        for raw_indicator in raw_data:
            try:
                normalized = self._normalize_indicator(raw_indicator)
                if normalized:
                    normalized_iocs.append(normalized)
            except Exception as e:
                self.logger.warning(f"Error normalizing indicator: {e}")
                continue

        return normalized_iocs

    def _normalize_indicator(self, raw_indicator: Dict) -> Optional[Dict]:
        """
        Normalize a single OTX indicator

        Args:
            raw_indicator: Raw indicator from OTX

        Returns:
            Normalized IOC dictionary or None
        """
        try:
            # Extract basic fields
            indicator_value = raw_indicator.get("indicator")
            indicator_type_raw = raw_indicator.get("type")

            if not indicator_value or not indicator_type_raw:
                return None

            # Map OTX type to our IOCType
            ioc_type = self._map_otx_type_to_ioc_type(indicator_type_raw)
            if not ioc_type:
                self.logger.debug(f"Unmapped OTX type: {indicator_type_raw}")
                return None

            # Map OTX role to our IOCRole
            ioc_role = self._map_otx_role_to_ioc_role(raw_indicator.get("role"))

            # Build normalized IOC
            normalized = {
                "indicator": indicator_value,
                "ioc_type": ioc_type,
                "role": ioc_role,
                "confidence": self._calculate_confidence(raw_indicator),
                "source": "OTX",
                "source_feed_name": raw_indicator.get("pulse_name"),
                "source_reference_url": raw_indicator.get("source_data", {}).get("url"),
                "description": raw_indicator.get("title", ""),
                "first_seen": raw_indicator.get("created"),
                "last_seen": raw_indicator.get("modified"),
                "last_updated": datetime.utcnow().isoformat(),
                "tags": raw_indicator.get("pulse_tags", []),
                "is_active": True,
                "metadata": {
                    "otx_pulse_id": raw_indicator.get("pulse_id"),
                    "otx_indicator_id": raw_indicator.get("id"),
                    "otx_type": indicator_type_raw,
                    "otx_role": raw_indicator.get("role")
                }
            }

            return normalized

        except Exception as e:
            self.logger.error(f"Error normalizing indicator: {e}")
            return None

    def _map_otx_type_to_ioc_type(self, otx_type: str) -> Optional[str]:
        """
        Map OTX indicator type to our IOCType

        Args:
            otx_type: OTX type string

        Returns:
            IOCType enum value or None
        """
        # OTX type mapping
        mapping = {
            "IPv4": IOCType.IPV4,
            "IPv6": IOCType.IPV6,
            "domain": IOCType.DOMAIN,
            "hostname": IOCType.HOSTNAME,
            "url": IOCType.URL,
            "email": IOCType.EMAIL,
            "FileHash-MD5": IOCType.FILE_HASH_MD5,
            "FileHash-SHA1": IOCType.FILE_HASH_SHA1,
            "FileHash-SHA256": IOCType.FILE_HASH_SHA256,
            "CVE": IOCType.CVE,
            "ASN": IOCType.ASN,
        }

        return mapping.get(otx_type)

    def _map_otx_role_to_ioc_role(self, otx_role: Optional[str]) -> str:
        """
        Map OTX role to our IOCRole

        Args:
            otx_role: OTX role string

        Returns:
            IOCRole enum value
        """
        if not otx_role:
            return IOCRole.UNKNOWN

        # OTX role mapping
        mapping = {
            "malware": IOCRole.MALWARE,
            "botnet": IOCRole.BOTNET,
            "command_and_control": IOCRole.COMMAND_AND_CONTROL,
            "c2": IOCRole.COMMAND_AND_CONTROL,
            "phishing": IOCRole.PHISHING,
            "spam": IOCRole.SPAM,
            "ddos": IOCRole.DDoS,
            "exploit": IOCRole.EXPLOIT,
        }

        return mapping.get(otx_role, IOCRole.UNKNOWN)

    def _calculate_confidence(self, raw_indicator: Dict) -> int:
        """
        Calculate confidence score for indicator

        Args:
            raw_indicator: Raw indicator

        Returns:
            Confidence score 0-100
        """
        # OTX doesn't provide confidence, so we estimate based on data

        base_confidence = 70  # Default base

        # Increase if has multiple sources
        if raw_indicator.get("pulse_tags"):
            base_confidence += 10

        # Increase if has description
        if raw_indicator.get("title"):
            base_confidence += 5

        # Cap at 100
        return min(base_confidence, 100)
