"""Offline safeguards and fixtures for gate correctness regression tests."""
import importlib.util
import pathlib
import re
import socket
import sys

import boto3
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agent"))

# A Python or pip command word in shell text: python, python3, .venv/bin/python,
# "$RUNNER_TEMP/reviewer-venv/bin/python", pip, pip3 ...
_PY_CALL = re.compile(r'(?:^|[\s;&|(`])["\']?((?:[\w.${}/-]*/)?(?:python3?|pip3?))["\']?(?=[\s;)]|$)')


def unisolated_python(text):
    """Every Python call in `text` that is not `python -I`, and every bare pip call."""
    found = []
    for match in _PY_CALL.finditer(text):
        if text[:match.start(1)].rstrip(" \"'").endswith(" -m"):
            continue                      # `python -I -m pip`: the python call is checked
        word = match.group(1).rsplit("/", 1)[-1]
        rest = text[match.end():].lstrip()
        if word.startswith("pip"):
            if re.match(r"(install|download|wheel|uninstall)\b", rest):   # a pip run, not
                found.append(text[match.start():match.end() + 30].strip())  # `--upgrade pip`
        elif not rest.startswith("-I "):
            found.append(text[match.start():match.end() + 30].strip())
    return found


@pytest.fixture(autouse=True)
def no_external_calls(monkeypatch):
    def refused(*args, **kwargs):
        raise AssertionError("offline test attempted network/AWS access")

    monkeypatch.setattr(socket.socket, "connect", refused)
    monkeypatch.setattr(boto3, "client", refused)


@pytest.fixture
def load_module():
    def load(relative):
        spec = importlib.util.spec_from_file_location(
            pathlib.Path(relative).stem, ROOT / relative)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    return load
