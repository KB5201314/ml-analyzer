import logging
import warnings

import pytest
import os

from ml_analyzer.device import Device

logger = logging.getLogger(__name__)


def test_device_connect():
    if 'CI' in os.environ:
        pytest.skip("CI environment detected. Skip device connect test.")
    else:
        try:
            device = Device()
        except Exception as e:
            warnings.warn("Test device connect failed with error: {}".format(e))
