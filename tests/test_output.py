"""Tests for output formatters."""

import json

from netrecon.output import print_json, print_csv, export_results


def test_print_json(capsys):
    """print_json should output valid JSON."""
    data = [{"port": 80, "state": "open", "service": "http"}]
    print_json(data)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed[0]["port"] == 80
    assert parsed[0]["state"] == "open"


def test_print_json_single_dict(capsys):
    """print_json should handle a single dict."""
    data = {"os_guess": "Linux", "confidence": 85}
    print_json(data)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["os_guess"] == "Linux"


def test_print_csv(capsys):
    """print_csv should output valid CSV."""
    data = [
        {"port": 22, "state": "open", "service": "ssh"},
        {"port": 80, "state": "open", "service": "http"},
    ]
    print_csv(data)
    captured = capsys.readouterr()
    assert "port,state,service" in captured.out
    assert "22,open,ssh" in captured.out
    assert "80,open,http" in captured.out


def test_print_csv_empty(capsys):
    """print_csv should handle empty data."""
    print_csv([])
    captured = capsys.readouterr()
    assert captured.out == ""


def test_export_json(tmp_path):
    """export_results should write JSON to file."""
    data = [{"port": 443, "state": "open"}]
    path = tmp_path / "results.json"
    result = export_results(data, "json", str(path))
    assert result == str(path)

    with open(path) as f:
        parsed = json.load(f)
    assert parsed[0]["port"] == 443


def test_export_csv(tmp_path):
    """export_results should write CSV to file."""
    data = [{"port": 22, "state": "open"}]
    path = tmp_path / "results.csv"
    result = export_results(data, "csv", str(path))
    assert result == str(path)

    with open(path) as f:
        content = f.read()
    assert "port,state" in content
    assert "22,open" in content