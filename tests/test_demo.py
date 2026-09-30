"""Smoke test: the README quickstart demo runs and prints what the README shows."""

import runpy
import shutil
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo.py"


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
def test_demo_output(capsys):
    runpy.run_path(str(DEMO), run_name="__main__")
    out = capsys.readouterr().out
    assert "Staged synthetic_cohort.vcf.gpg: status=staged, encrypted=True" in out
    assert "Refused: synthetic_cohort.vcf does not look like an encrypted OpenPGP message" in out
    assert "Recipient check: 1/1 verified" in out
