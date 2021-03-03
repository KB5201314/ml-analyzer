import logging

import delegator
import frida

logger = logging.getLogger(__name__)


class Device:
    """A connected device

    Attributes:
        adb_serial: A `str` value or `None`, which can be used to identify a connected android 
            device. `adb_serial` can be found by `adb device -l`, which usually the first column 
            of the result. For usb connected device, the value is usually a hexadecimal number 
            of length eight (e.g., 154af8ef). For remote connected device, the value is `ip:port`, 
            (e.g., 192.168.123.202:5555). It should be noted that frida uses `adb_serial` as the 
            `Id` of device, which can be seem by executing `frida-ls-devices`.
    """

    def __init__(self, adb_serial=None):
        self.adb_serial = adb_serial
        # try connect via adb
        ret = self.adb_run('shell')
        if ret != 0:
            raise RuntimeError(
                'device is not connected via `adb`. adb_serial: `{}`, return value is {}'.format(self.adb_serial, ret))
        # try connect via frida
        try:
            if adb_serial != None:
                self.frida_device = frida.get_device(id=adb_serial)
            else:
                self.frida_device = frida.get_usb_device()
                self.frida_device.enumerate_processes()
        except frida.ServerNotRunningError as e:
            raise RuntimeError(
                'device is connected via `frida`, but `frida-server` is not running. adb_serial: `{}`'.format(self.adb_serial)) from e
        except frida.InvalidArgumentError as e:
            raise RuntimeError(
                'device is not connected via `frida`, please check whether frida\'s output contains devices with adb_serial: `{}`'.format(self.adb_serial)) from e

    def adb_run(self, cmd: str) -> int:
        if self.adb_serial == None:
            cmd = 'adb {}'.format(cmd)
        else:
            cmd = 'adb -s {} {}'.format(self.adb_serial, cmd)
        c = delegator.run(cmd)
        logger.debug("outside command finished with return_code {}, cmd : `{}`".format(
            c.return_code, cmd))
        return c.return_code

    def adb_install_apk(self, apk_path: str) -> bool:
        logger.debug('device: {} install apk: {}'.format(self, apk_path))
        return self.adb_run('install {}'.format(apk_path)) == 0

    def adb_uninstall_pkg(self, pkg_name: str) -> bool:
        logger.debug('device: {} uninstall pkg: {}'.format(self, pkg_name))
        return self.adb_run('uninstall {}'.format(pkg_name)) == 0

    def adb_start_pkg(self, pkg_name: str) -> bool:
        logger.debug('device: {} start pkg: {}'.format(self, pkg_name))
        return self.adb_run('adb shell monkey -p {} -c android.intent.category.LAUNCHER 1'.format(pkg_name)) == 0

    def __repr__(self):
        return '<Device adb_serial={}>'.format(self.adb_serial)

    def __str__(self):
        return self.__repr__()
