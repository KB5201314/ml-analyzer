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
        d = device.frida_device
        pid = d.spawn("com.dsrtech.lipsy")
        session = d.attach(pid)
        script = session.create_script(
            util.read_frida_script('extractor_script_enumerate_ranges.js'))

        def on_message(msg, bs):
            logger.debug(msg)
            assert len(bs) == msg['payload']['size']
        script.on('message', on_message)
        script.load()
        d.resume(pid)
        script.exports.run()
        time.sleep(1)

    get_device_then(callback)


def test_device_hook_deallocation():
    def callback(device: Device):
        # we assume that model file size is at least 1K
        min_model_size = 1024

        d = device.frida_device
        pid = d.spawn("com.dsrtech.lipsy")
        session = d.attach(pid)
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_deallocation.js'))

        def on_message(msg, bs):
            logger.debug(msg)
            assert int(msg['payload']['pointer'], 16) != 0
            assert int(msg['payload']['size']) >= min_model_size
            assert len(bs) == msg['payload']['size']

        script.on('message', on_message)

        script.load()
        d.resume(pid)
        script.exports.run(min_model_size)
        time.sleep(1)
        script.unload()
        session.detach()

    get_device_then(callback)


def test_device_read_file():
    def callback(device: Device):
        ret_1, file_content = device.adb_read_file(
            '/data/local/tmp/frida-server')
        ret_2, md5 = device.adb_run(
            'shell md5sum -b /data/local/tmp/frida-server')
        assert ret_1 == 0
        assert ret_2 == 0
        assert len(file_content) > 0
        assert util.md5_of_bytes(file_content).lower() == md5.strip().lower()

    get_device_then(callback)


def test_device_adb_get_data_dir_of_pkg():
    def callback(device: Device):
        ret, data_dir = device.adb_get_data_dir_of_pkg('com.dsrtech.lipsy')
        assert ret == 0
        assert data_dir == '/data/user/0/com.dsrtech.lipsy'

    get_device_then(callback)


def test_device_hook_file_access():
    def callback(device: Device):
        # get data_dir
        ret, data_dir = device.adb_get_data_dir_of_pkg('com.dsrtech.lipsy')
        assert ret == 0
        files_dir = '{}/files'.format(data_dir)
        # spawn app and test script
        d = device.frida_device
        pid = d.spawn("com.dsrtech.lipsy")
        session = d.attach(pid)
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_file_access.js'))

        def on_message(msg, bs):
            logger.debug(msg)
            # FIXME: fix exception in frida callback can was catch by frida-core, we need to throw out them
            assert msg['payload']['file_path'].startswith('files_dir')

        script.on('message', on_message)
        script.load()
        d.resume(pid)
        script.exports.run([files_dir])
        time.sleep(10)
        script.unload()
        session.detach()

    get_device_then(callback)
