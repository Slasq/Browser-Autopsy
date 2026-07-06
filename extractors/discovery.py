"""
discovery.py — find browser profiles inside an evidence directory.

Supports the `--input ./artifacts/` workflow: an investigator copies whole
profile folders (possibly several browsers, several machines) into one
directory and the tool figures out what is what.

Detection is artifact-based, not name-based:
  - a directory containing 'History'        -> Chromium-family profile
  - a directory containing 'places.sqlite'  -> Gecko-family profile

The browser LABEL (chrome / edge / tor / ...) is a best-effort guess from the
directory path; when nothing matches, the engine default is used
(chrome / firefox). The label only affects event naming — parsing is
identical within an engine family.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from extractors.chrome import CHROMIUM_BROWSERS
from extractors.firefox import GECKO_BROWSERS


@dataclass(frozen=True)
class DiscoveredProfile:
    """One browser profile found under the input directory."""
    engine: str    # "chromium" | "gecko"
    browser: str   # label for event naming (chrome, edge, tor, ...)
    path: Path     # profile directory (contains History / places.sqlite)


def _guess_label(relative: str, engine: str) -> str:
    """Guess the browser label from a profile's relative path.

    Longer names are checked first so 'chromium' wins over 'chrome' and
    'librewolf' is never mistaken for 'firefox'.
    """
    haystack = relative.lower().replace("\\", "/")
    labels = CHROMIUM_BROWSERS if engine == "chromium" else GECKO_BROWSERS
    for label in sorted(labels, key=len, reverse=True):
        if label in haystack:
            return label
    return "chrome" if engine == "chromium" else "firefox"


def _classify(directory: Path) -> str | None:
    """Return the engine of `directory` if it is a profile, else None."""
    if (directory / "History").is_file():
        return "chromium"
    if (directory / "places.sqlite").is_file():
        return "gecko"
    return None


def discover_profiles(input_dir: Path) -> list[DiscoveredProfile]:
    """Recursively find all browser profiles in `input_dir`.

    The input directory itself may be a profile, or contain any number of
    profile folders at any depth. Once a directory is identified as a
    profile, its subdirectories are not descended into (a profile never
    nests another profile).

    Args:
        input_dir: Evidence directory to scan.

    Returns:
        List of DiscoveredProfile sorted by path (deterministic order).

    Raises:
        FileNotFoundError: If `input_dir` does not exist or is not a directory.
    """
    if not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    found: list[DiscoveredProfile] = []

    def _scan(directory: Path) -> None:
        engine = _classify(directory)
        if engine is not None:
            relative = str(directory.relative_to(input_dir))
            if relative == ".":  # input dir itself is the profile
                relative = directory.name
            found.append(DiscoveredProfile(
                engine=engine,
                browser=_guess_label(relative, engine),
                path=directory,
            ))
            return  # profile found — don't descend further
        for child in sorted(directory.iterdir()):
            if child.is_dir():
                _scan(child)

    _scan(input_dir)
    found.sort(key=lambda p: str(p.path))
    return found
