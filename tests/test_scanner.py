"""Unit tests for scanner.py — target/flag validation and run_scan()."""

from unittest import mock

import pytest

from scanner import validate_target, validate_flags, run_scan


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------

def test_valid_ipv4():
    assert validate_target("192.168.1.1") is True


def test_valid_cidr():
    assert validate_target("10.0.0.0/24") is True


def test_valid_hostname():
    assert validate_target("example.com") is True


def test_valid_ipv6():
    assert validate_target("2001:db8::1") is True


def test_empty_target():
    assert validate_target("") is False


def test_target_too_long():
    assert validate_target("a" * 256) is False


def test_target_shell_metachar_semicolon():
    assert validate_target("192.168.1.1; rm -rf /") is False


def test_target_with_space():
    assert validate_target("192.168.1.1 192.168.1.2") is False


def test_target_with_backtick():
    assert validate_target("host`id`") is False


def test_target_with_dollar():
    assert validate_target("192.168.1.$host") is False


def test_target_leading_dash_rejected():
    # A target starting with "-" would be parsed by nmap as an option
    # rather than a positional argument, bypassing the flag allowlist.
    assert validate_target("-iL/etc/passwd") is False
    assert validate_target("--script=evil") is False


# ---------------------------------------------------------------------------
# validate_flags
# ---------------------------------------------------------------------------

def test_empty_flags():
    valid, err = validate_flags("")
    assert valid is True
    assert err is None


def test_whitespace_only_flags():
    valid, err = validate_flags("   ")
    assert valid is True
    assert err is None


def test_valid_single_flag():
    valid, err = validate_flags("-sV")
    assert valid is True
    assert err is None


def test_valid_multiple_flags():
    # -p is in ALLOWED_FLAGS; "80,443" is a value token (no leading dash)
    valid, err = validate_flags("-sV -T4 -p 80,443")
    assert valid is True
    assert err is None


def test_disallowed_flag():
    valid, err = validate_flags("--script vuln")
    assert valid is False
    assert "--script" in err


def test_flag_with_equals_value_allowed():
    # --top-ports is in ALLOWED_FLAGS; split on "=" gives --top-ports
    valid, err = validate_flags("--top-ports=100")
    assert valid is True
    assert err is None


def test_allowed_open_flag():
    valid, err = validate_flags("--open")
    assert valid is True
    assert err is None


def test_disallowed_version_script_flag():
    valid, err = validate_flags("--version-all")
    assert valid is False


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------

def test_run_scan_returns_xml_path(tmp_path):
    mock_result = mock.MagicMock()
    mock_result.returncode = 0
    with mock.patch("scanner.subprocess.run", return_value=mock_result) as mock_run:
        path = run_scan("192.168.1.1", "-sV", str(tmp_path))
    assert path.endswith(".xml")
    assert str(tmp_path) in path
    # Target must follow a "--" separator so nmap can't misparse it as a flag.
    cmd = mock_run.call_args[0][0]
    assert cmd[-2:] == ["--", "192.168.1.1"]


def test_run_scan_invalid_target_raises(tmp_path):
    with pytest.raises(ValueError):
        run_scan("bad target!", "", str(tmp_path))


def test_run_scan_invalid_flags_raises(tmp_path):
    with pytest.raises(ValueError):
        run_scan("192.168.1.1", "--script evil", str(tmp_path))


def test_run_scan_nmap_not_installed(tmp_path):
    with mock.patch("scanner.subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(RuntimeError, match="not installed"):
            run_scan("192.168.1.1", "", str(tmp_path))


def test_run_scan_nmap_nonzero_exit(tmp_path):
    mock_result = mock.MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "Permission denied"
    with mock.patch("scanner.subprocess.run", return_value=mock_result):
        with pytest.raises(RuntimeError):
            run_scan("192.168.1.1", "", str(tmp_path))
