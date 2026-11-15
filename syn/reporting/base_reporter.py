"""
SYN - Base Reporter Interface & Shared Normalization Helpers
"""

from abc import ABC, abstractmethod
import math
import os
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from syn.core.config import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
    STATUS_ERROR,
    STATUS_FILTERED,
    STATUS_OPEN,
    STATUS_OPEN_FILTERED,
    STATUS_UNFILTERED,
    get_reports_dir,
)
from syn.scanner.service_identifier import ServiceIdentifier

_LEGACY_RISK_MAP = {
    "KRİTİK": RISK_CRITICAL,
    "CRITICAL": RISK_CRITICAL,
    "CRITICAL RISK": RISK_CRITICAL,
    "YÜKSEK": RISK_HIGH,
    "HIGH": RISK_HIGH,
    "HIGH RISK": RISK_HIGH,
    "ORTA": RISK_MEDIUM,
    "MEDIUM": RISK_MEDIUM,
    "MEDIUM RISK": RISK_MEDIUM,
    "DÜŞÜK": RISK_LOW,
    "DÜÅžÜK": RISK_LOW,
    "LOW": RISK_LOW,
    "LOW RISK": RISK_LOW,
    "NO_ACTION": RISK_NONE,
    "SAFE": RISK_NONE,
}


class BaseReporter(ABC):
    """Abstract base class for SYN report exporters (OCP / LSP / DRY)."""

    @abstractmethod
    def generate(
        self,
        results: List[Dict[str, Any]],
        cve_engine: Any,
        filename: Optional[str] = None,
    ) -> str:
        """Generate a report and return output identifier or path."""
        raise NotImplementedError

    @staticmethod
    def normalize_risk(decision: Any) -> str:
        key = str(decision or "").strip().upper()
        return _LEGACY_RISK_MAP.get(key, RISK_NONE if not key else str(decision))

    @staticmethod
    def normalize_os(result: Dict[str, Any]) -> str:
        os_guess = result.get("ai_os_tahmini", "Unknown")
        if isinstance(os_guess, (list, np.ndarray)):
            os_guess = str(os_guess[0]) if len(os_guess) > 0 else "Unknown"
        return str(os_guess or "Unknown")

    @staticmethod
    def resolve_output_path(filename: Optional[str], default_filename: str) -> str:
        target = filename or default_filename
        reports_dir = get_reports_dir()
        # If no explicit directory part and REPORTS_DIR is configured away from '.', place inside REPORTS_DIR
        if not os.path.dirname(target) and reports_dir not in (".", ""):
            os.makedirs(reports_dir, exist_ok=True)
            target = os.path.join(reports_dir, target)
        else:
            parent = os.path.dirname(target)
            if parent:
                os.makedirs(parent, exist_ok=True)
        return target

    @staticmethod
    def format_banner_display(res: Dict[str, Any]) -> str:
        """Return concise display banner, summarizing raw HTTP headers cleanly."""
        summary = str(res.get("banner_summary") or "").strip()
        if summary:
            return summary
        raw_banner = str(res.get("banner") or "")
        if not raw_banner:
            return "-"
        port_raw = res.get("port", 0)
        port_val = port_raw if isinstance(port_raw, int) else 0
        return ServiceIdentifier.summarize_banner(port_val, raw_banner) or "-"

    @staticmethod
    def summarize_web_info(web_info: Any) -> Dict[str, Any]:
        if not isinstance(web_info, dict) or not web_info.get("is_web"):
            return {}
        tls_summary = ""
        tls_info = web_info.get("tls_info")
        if isinstance(tls_info, dict) and tls_info.get("tls_version"):
            trust = "Trusted Cert" if tls_info.get("cert_verified") else "Untrusted Cert"
            tls_summary = f"{tls_info['tls_version']} ({trust})"
        return {
            "scheme": str(web_info.get("scheme") or "http"),
            "title": str(web_info.get("title") or "Unknown"),
            "waf": str(web_info.get("waf") or "None Detected"),
            "has_robots": bool(web_info.get("has_robots")),
            "missing_headers": list(web_info.get("missing_security_headers") or []),
            "tls_summary": tls_summary,
        }

    @staticmethod
    def partition_display_rows(
        results: List[Dict[str, Any]], cve_engine: Any
    ) -> Tuple[List[Tuple[Dict[str, Any], Dict[str, str]]], int, int]:
        """
        Filter reportable rows, evaluate CVEs once per row, and cap noisy OPEN|FILTERED floods.
        Returns (rows_with_risk, skipped_open_filtered_count, error_count).
        """
        open_filtered_count = sum(
            1 for r in results if r.get("status") == STATUS_OPEN_FILTERED
        )
        error_count = sum(1 for r in results if r.get("status") == STATUS_ERROR)
        suppress_open_filtered = open_filtered_count > 20

        # Show ACK scan statuses (UNFILTERED/FILTERED) only when ACK statuses exist and OPEN isn't dominant
        has_ack_unfiltered = any(r.get("status") == STATUS_UNFILTERED for r in results)
        allowed_statuses = {STATUS_OPEN, STATUS_OPEN_FILTERED}
        if has_ack_unfiltered:
            allowed_statuses.update({STATUS_UNFILTERED, STATUS_FILTERED})

        rows: List[Tuple[Dict[str, Any], Dict[str, str]]] = []
        skipped = 0

        for res in results:
            status = res.get("status")
            if status not in allowed_statuses:
                continue
            if status == STATUS_OPEN_FILTERED and suppress_open_filtered:
                skipped += 1
                continue
            risk_info = cve_engine.evaluate_result(res)
            risk_info = dict(risk_info)
            risk_info["decision"] = BaseReporter.normalize_risk(risk_info.get("decision"))
            rows.append((res, risk_info))

        return rows, skipped, error_count

    @staticmethod
    def to_json_safe(value: Any) -> Any:
        """Recursively convert numpy, Scapy, and non-RFC-8259 float values to JSON-safe types."""
        if value is None or isinstance(value, (bool, str, int)):
            if isinstance(value, np.integer):
                return int(value)
            return value
        if isinstance(value, float):
            return None if (math.isnan(value) or math.isinf(value)) else value
        if isinstance(value, np.integer):
            return int(value)
        if isinstance(value, np.floating):
            fval = float(value)
            return None if (math.isnan(fval) or math.isinf(fval)) else fval
        if isinstance(value, np.ndarray):
            return [BaseReporter.to_json_safe(item) for item in value.tolist()]
        if isinstance(value, dict):
            return {str(k): BaseReporter.to_json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [BaseReporter.to_json_safe(item) for item in value]
        # Scapy FlagValue or custom types: preserve int when supported, else string
        try:
            return int(value)
        except Exception:
            return str(value)
