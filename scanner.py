"""Run nmap scans via subprocess with input validation."""

import logging
import os
import re
import shlex
import subprocess
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Flags that are allowed in user input (common, safe nmap options)
ALLOWED_FLAGS = {
    "-sS", "-sT", "-sU", "-sV", "-sC", "-sn", "-sP",
    "-O", "-A", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "-p", "-F", "--top-ports", "-Pn", "-n", "-v", "-vv",
    "--open", "--version-intensity",
}

# Pattern for valid scan targets (IPs, CIDR, hostnames)
TARGET_PATTERN = re.compile(
    r"^[a-zA-Z0-9.\-:/]+$"
)


def validate_target(target: str) -> bool:
    """Validate that a scan target looks like a legitimate IP, CIDR, or hostname.

    Args:
        target: The scan target string to validate.

    Returns:
        True if the target appears valid, False otherwise.
    """
    if not target or len(target) > 255:
        return False
    if target.startswith("-"):
        # Targets starting with "-" would be parsed as an nmap option rather
        # than a positional argument, bypassing the flag allowlist entirely
        # (e.g. "-iL/etc/passwd" or "--script=...").
        return False
    return bool(TARGET_PATTERN.match(target))


def validate_flags(flags: str) -> tuple[bool, Optional[str]]:
    """Validate that user-supplied nmap flags are in the allowed set.

    Args:
        flags: Space-separated nmap flags string.

    Returns:
        Tuple of (is_valid, error_message). error_message is None if valid.
    """
    if not flags.strip():
        return True, None

    tokens = shlex.split(flags)
    for token in tokens:
        if token.startswith("-"):
            # Check flag itself (strip any value attached with =)
            flag_name = token.split("=")[0]
            if flag_name not in ALLOWED_FLAGS:
                return False, f"Flag not allowed: {flag_name}"
    return True, None


def run_scan(target: str, flags: str, output_dir: str) -> str:
    """Execute an nmap scan and save XML output.

    Args:
        target: The scan target (IP, CIDR, or hostname).
        flags: Additional nmap flags.
        output_dir: Directory to store the XML output file.

    Returns:
        Path to the generated XML output file.

    Raises:
        ValueError: If target or flags fail validation.
        RuntimeError: If nmap exits with an error.
    """
    if not validate_target(target):
        raise ValueError(f"Invalid scan target: {target}")

    valid, err = validate_flags(flags)
    if not valid:
        raise ValueError(err)

    os.makedirs(output_dir, exist_ok=True)
    timestamp = int(time.time())
    output_file = os.path.join(output_dir, f"scan_{timestamp}.xml")

    # Build command — never use shell=True
    cmd = ["nmap"]
    if flags.strip():
        cmd.extend(shlex.split(flags))
    cmd.extend(["-oX", output_file, "--", target])

    logger.info("Running nmap: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        raise RuntimeError("nmap is not installed or not in PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Scan timed out after 600 seconds.")

    if result.returncode != 0:
        logger.error("nmap stderr: %s", result.stderr)
        raise RuntimeError(f"nmap exited with code {result.returncode}: {result.stderr}")

    logger.info("Scan complete. Output saved to %s", output_file)
    return output_file
