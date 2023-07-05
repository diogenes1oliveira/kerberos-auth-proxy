import os
from typing import Mapping

import pytest

from kerberos_auth_proxy.utils import (
    env_to_map,
)


@pytest.mark.parametrize(
    "environ,expected_result", [
        ({}, {}),
        ({'TEST_VALUE': ''}, {}),
        ({'TEST_VALUE': 'external=local:8080 a=https://b:443'}, {'external': 'local:8080', 'a': 'https://b:443'}),
    ],
)
def test_env_to_map(environ: Mapping[str, str], expected_result):
    os.environ = environ

    assert env_to_map('TEST_VALUE') == expected_result
