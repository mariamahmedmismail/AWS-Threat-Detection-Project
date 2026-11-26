"""boto3 clients with standard retries (up to 3 attempts, API doc section 8)."""
import functools

import boto3
from botocore.config import Config

_RETRY = Config(retries={"mode": "standard", "max_attempts": 3})


@functools.lru_cache(maxsize=None)
def client(service: str, region: str | None = None):
    return boto3.client(service, region_name=region, config=_RETRY)


def reset_clients():
    """Used by tests so each test gets fresh (mocked) clients."""
    client.cache_clear()
