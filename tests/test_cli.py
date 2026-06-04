import subprocess
import sys


def test_cli_loads_demo_data_and_prints_ascii():
    result = subprocess.run(
        [
            sys.executable,
            "pentest_graph.py",
            "--nmap",
            "demo/nmap_sample.xml",
            "--bh",
            "demo/bloodhound_sample.json",
            "--ascii",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "ASCII graph" in result.stdout
    assert "exposes" in result.stdout


def test_cli_accepts_neo4j_clear_flag_without_exporting():
    result = subprocess.run(
        [sys.executable, "pentest_graph.py", "--neo4j-clear", "--ascii"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "ASCII graph" in result.stdout
