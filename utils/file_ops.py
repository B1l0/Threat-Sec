from pathlib import Path
from typing import Set, List
import logging

logger = logging.getLogger("ThreatIntel")

def read_file_lines(filepath: str) -> Set[str]:
    """
    Reads a file and returns a set of unique, non-empty, stripped lines.
    Ignores lines starting with #.
    """
    path = Path(filepath)
    if not path.exists():
        logger.warning(f"File not found: {filepath}")
        return set()

    lines = set()
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                content = line.strip()
                if content and not content.startswith("#"):
                    lines.add(content)
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")

    return lines

def write_output_file(filepath: str, lines: List[str]) -> None:
    """
    Writes a list of strings to a file, one per line.
    """
    path = Path(filepath)
    try:
        with path.open("w", encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line}\n")
        logger.info(f"Successfully wrote {len(lines)} lines to {filepath}")
    except Exception as e:
        logger.error(f"Error writing to file {filepath}: {e}")
