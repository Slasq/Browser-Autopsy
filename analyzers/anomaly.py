"""
anomaly.py — flag suspicious activity in a unified timeline.

Three detectors (v1, per roadmap):
  1. detect_suspicious_domains   — visits/downloads to domains on IOC list
  2. detect_suspicious_extensions — risky download extensions (incl. the
                                    double-extension trick like invoice.pdf.exe)
  3. detect_suspicious_keywords  — searches containing suspicious terms

Input  : list[TimelineEvent] from analyzers.timeline.build_timeline()
Output : list[Anomaly] sorted chronologically

IOCs are loaded from a YAML config (default config/iocs.yaml in the repo
root, overridable with the --ioc-file CLI flag).

ASSUMED TimelineEvent.details schema (set by adapters in timeline.py):
  - visit events    : details["url"]         (str)
  - download events : details["filename"]    (str, basename) — falls back
                      details["target_path"] (str)            to basename of target_path
                      details["url"]         (str, optional)  used for domain check
  - search events   : details["query"]       (str)

If your adapters use different keys, only three lines need to change
(the .get("...") calls in the three detector functions).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import yaml

from analyzers.timeline import TimelineEvent
from extractors.base import basename


# Models
@dataclass(frozen=True)
class IOCs:
    """Indicators of Compromise loaded from a YAML config file."""
    suspicious_domains: frozenset[str]
    suspicious_extensions: frozenset[str]
    suspicious_keywords: frozenset[str]


@dataclass(frozen=True)
class Anomaly:
    """A single anomaly detected in the timeline."""
    event: TimelineEvent
    rule_id: str        # SUSPICIOUS_DOMAIN | SUSPICIOUS_EXTENSION |
                        # DOUBLE_EXTENSION  | SUSPICIOUS_KEYWORD
    severity: str       # low | medium | high
    reason: str         # human-readable explanation
    matched_value: str  # the IOC entry that matched (for audit trail)


# Config loading
class IOCConfigError(ValueError):
    """The IOC file exists but is unusable: broken YAML or wrong structure."""


def _ioc_list(data: dict, key: str, path: Path) -> list:
    """Return the entries under `key`, validated to be a YAML list."""
    raw = data.get(key) or []
    # skalar zamiast listy ("suspicious_keywords: mimikatz") iterowałby się
    # po literach i każda litera stałaby się osobnym IOC
    if not isinstance(raw, list):
        raise IOCConfigError(
            f"'{key}' in IOC file {path} must be a list, got {type(raw).__name__}"
        )
    # pusty element listy to None w YAML-u, a str(None) dałoby IOC "none"
    return [entry for entry in raw if entry is not None and str(entry).strip()]


def load_iocs(path: Path) -> IOCs:
    """Load IOCs from a YAML file.

    Normalisation:
      - everything lowercased (matching is case-insensitive)
      - extensions get a leading dot if missing in YAML ("exe" -> ".exe")
      - missing top-level keys / empty file => empty frozenset(s)
      - empty list entries are dropped

    Raises FileNotFoundError when `path` does not exist.
    Raises IOCConfigError when the YAML is broken or a category is not a list.
    """
    if not path.exists():
        raise FileNotFoundError(f"IOC config file not found: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise IOCConfigError(f"Invalid YAML in IOC file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise IOCConfigError(
            f"IOC file {path} must map category names to lists, "
            f"got {type(data).__name__}"
        )

    # extensions: dopuszczamy "exe" i ".exe" w YAMLu — wewnątrz trzymamy z kropką
    extensions: list[str] = []
    for ext in _ioc_list(data, "suspicious_extensions", path):
        ext = str(ext).lower().strip()
        if not ext.startswith("."):
            ext = "." + ext
        extensions.append(ext)

    return IOCs(
        suspicious_domains=frozenset(
            str(d).lower().strip() for d in _ioc_list(data, "suspicious_domains", path)
        ),
        suspicious_extensions=frozenset(extensions),
        suspicious_keywords=frozenset(
            str(k).lower().strip() for k in _ioc_list(data, "suspicious_keywords", path)
        ),
    )


# Helpers
def _domain_from_url(url: str) -> str:
    """Extract lowercase domain from URL, stripped of 'www.', port and login.

    Returns '' for a URL without a host and for a malformed URL.
    """
    try:
        # hostname (nie netloc) odcina login, hasło i port:
        # "user:pass@pastebin.com:8080" -> "pastebin.com"
        domain = urlparse(url).hostname or ""
    except ValueError:  # np. niedomknięty nawias adresu IPv6
        return ""
    domain = domain.rstrip(".")  # "pastebin.com." to ta sama domena
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _domain_matches(domain: str, iocs: Iterable[str]) -> str | None:
    """Return the IOC entry that matched, or None.

    Matching rules:
      - "*.tld" -> suffix match (e.g. "*.onion" matches "abc.onion")
      - everything else -> exact equality (subdomains are NOT a match)
    """
    for ioc in iocs:
        if ioc.startswith("*."):
            if domain.endswith(ioc[1:]):  # zostawiamy kropkę -> ".onion"
                return ioc
        elif domain == ioc:
            return ioc
    return None


# Innocent-looking extensions used in the double-extension trick.
# Constant (not a config) — these are document/media types that an executable
# WOULD masquerade as. Not subject to investigator customisation.
_BENIGN_LOOKING_EXTS: frozenset[str] = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".csv", ".rtf",
    ".mp3", ".mp4", ".avi", ".mov", ".zip",
})


# Detectors
def detect_suspicious_domains(
    events: list[TimelineEvent],
    suspicious_domains: frozenset[str],
) -> list[Anomaly]:
    """Flag events whose URL's domain matches the IOC list.

    Checked: visit & download events.
    Skipped: search events — their netloc is the search engine (google.com
             etc.) which would never be on an IOC list and just adds noise.
    """
    anomalies: list[Anomaly] = []
    for event in events:
        if "search" in event.event_type:
            continue
        url = event.details.get("url", "")
        if not url:
            continue
        domain = _domain_from_url(url)
        if not domain:
            continue
        match = _domain_matches(domain, suspicious_domains)
        if match is None:
            continue
        anomalies.append(Anomaly(
            event=event,
            rule_id="SUSPICIOUS_DOMAIN",
            severity="high",
            reason=f"Connection to suspicious domain '{domain}' (matched IOC: {match})",
            matched_value=match,
        ))
    return anomalies


def detect_suspicious_extensions(
    events: list[TimelineEvent],
    suspicious_extensions: frozenset[str],
) -> list[Anomaly]:
    """Flag download events for risky file types.

    Two outcomes:
      - final extension on IOC list                       -> SUSPICIOUS_EXTENSION (medium)
      - benign-looking second-to-last + risky last        -> DOUBLE_EXTENSION     (high)
        e.g. 'invoice.pdf.exe', 'photo.jpg.scr'
    """
    anomalies: list[Anomaly] = []
    for event in events:
        if "download" not in event.event_type:
            continue

        # primary: bare filename; fallback: derive from target_path
        filename = event.details.get("filename", "")
        if not filename:
            # target_path bywa None (pobranie bez ścieżki docelowej)
            filename = basename(event.details.get("target_path") or "")
        if not filename or "." not in filename:
            continue

        fn_lower = filename.lower()
        suffix = "." + fn_lower.rsplit(".", 1)[-1]
        if suffix not in suspicious_extensions:
            continue

        # check the second-to-last extension for the double-ext trick
        stem = fn_lower.rsplit(".", 1)[0]
        stem_suffix = ("." + stem.rsplit(".", 1)[-1]) if "." in stem else ""

        if stem_suffix in _BENIGN_LOOKING_EXTS:
            anomalies.append(Anomaly(
                event=event,
                rule_id="DOUBLE_EXTENSION",
                severity="high",
                reason=(
                    f"Double-extension trick: '{filename}' appears as "
                    f"'{stem_suffix}' but is actually '{suffix}'"
                ),
                matched_value=f"{stem_suffix}{suffix}",
            ))
        else:
            anomalies.append(Anomaly(
                event=event,
                rule_id="SUSPICIOUS_EXTENSION",
                severity="medium",
                reason=f"Downloaded file with risky extension '{suffix}'",
                matched_value=suffix,
            ))
    return anomalies


def detect_suspicious_keywords(
    events: list[TimelineEvent],
    suspicious_keywords: frozenset[str],
) -> list[Anomaly]:
    """Flag search events whose query contains a suspicious keyword.

    Substring match, case-insensitive. At most one anomaly per event even
    when multiple keywords match (avoids alert spam on noisy queries).
    """
    anomalies: list[Anomaly] = []
    for event in events:
        if "search" not in event.event_type:
            continue
        query = event.details.get("query", "")
        if not query:
            continue
        query_lower = query.lower()
        for keyword in suspicious_keywords:
            if keyword in query_lower:
                anomalies.append(Anomaly(
                    event=event,
                    rule_id="SUSPICIOUS_KEYWORD",
                    severity="medium",
                    reason=f"Search query contains suspicious keyword '{keyword}'",
                    matched_value=keyword,
                ))
                break  # one anomaly per event
    return anomalies


# Orchestrator
def detect(events: list[TimelineEvent], iocs: IOCs) -> list[Anomaly]:
    """Run all v1 detectors against the timeline, return sorted by time."""
    anomalies: list[Anomaly] = []
    anomalies.extend(detect_suspicious_domains(events, iocs.suspicious_domains))
    anomalies.extend(detect_suspicious_extensions(events, iocs.suspicious_extensions))
    anomalies.extend(detect_suspicious_keywords(events, iocs.suspicious_keywords))
    anomalies.sort(key=lambda a: (a.event.timestamp_utc is None, a.event.timestamp_utc))
    return anomalies