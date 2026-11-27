import pytest

from resume_request import common


@pytest.fixture(autouse=True)
def clear_secret_cache():
    common._secret_cache.clear()
    yield
    common._secret_cache.clear()
