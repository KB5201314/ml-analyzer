import logging
import warnings
import os
import time

import pytest
import frida

from ml_analyzer.device import Device
from ml_analyzer import util

logger = logging.getLogger(__name__)


def test_device_connect():
    get_device_then(lambda d: None)


def get_device_then(callback):
    if 'CI' in os.environ:
        pytest.skip("CI environment detected. Skip device connect test.")
    else:
        try:
            device = Device()
        except Exception as e:
            warnings.warn(
                "Test device connect failed with error: {}".format(e))
        else:
            callback(device)


def test_device_enumerate_ranges():
    def callback(device: Device):
        device = Device()
        d = device.frida_device
        pid = d.spawn("com.dsrtech.lipsy")
        session = d.attach(pid)
        script = session.create_script(
            util.read_frida_script('enumerate_ranges.js'))

        def on_message(msg, bs):
            logger.debug(msg)
            assert len(bs) == msg['payload']['size']
        script.on('message', on_message)
        script.load()
        d.resume(pid)
        script.exports.run()
        time.sleep(1)

    get_device_then(callback)
