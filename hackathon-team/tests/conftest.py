"""
Aegis Test Suite - conftest.py
Assumes middleware is running at BASE_URL (default: http://localhost:8080).
Set AEGIS_TEST_URL env var to override for Lightning AI.
"""
import os
import pytest
import httpx

BASE_URL = os.getenv("AEGIS_TEST_URL", "http://localhost:8080")

@pytest.fixture(scope="session")
def base_url():
    return BASE_URL

@pytest.fixture(scope="session")
def client():
    """Reusable sync httpx client for the test session."""
    with httpx.Client(base_url=BASE_URL, timeout=15.0) as c:
        yield c
