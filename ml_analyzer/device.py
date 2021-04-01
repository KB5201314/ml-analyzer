import logging

import delegator
import frida

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


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
        logger.info(
            "Connecting to device with adb_serial: {}".format(adb_serial))
        self.adb_serial = adb_serial
        # try connect via adb
        ret, _ = self.adb_run('shell exit')
        if ret != 0:
            raise RuntimeError(
                'device is not connected via `adb`. adb_serial: `{}`, return value of `adb shell` is {}'.format(self.adb_serial, ret))
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
        logger.info("Device connected. adb_serial: {}".format(adb_serial))

    def adb_run(self, cmd: str, binary_output=False) -> (int, bytes):
        if self.adb_serial == None:
            cmd = 'adb {}'.format(cmd)
        else:
            cmd = 'adb -s {} {}'.format(self.adb_serial, cmd)
        c = delegator.run(cmd, binary=binary_output)
        logger.debug("outside command finished with return_code {}, cmd : `{}`".format(
            c.return_code, cmd))
        return c.return_code, c.out

    def adb_read_file(self, absolute_path) -> (int, bytes):
        logger.debug('device: {} read file absolute_path: {}'.format(
            self, absolute_path))
        ret, content = self.adb_run('shell cat {}'.format(
            absolute_path), binary_output=True)
        logger.debug("device: {} read file failed with ret: {} absolute_path: {}".format(self,
                                                                                         ret, absolute_path))
        return ret, content

    def adb_install_apk(self, apk_path: str) -> bool:
        logger.debug('device: {} install apk: {}'.format(self, apk_path))
        return self.adb_run('install -r {}'.format(apk_path))[0] == 0

    def adb_uninstall_pkg(self, pkg_name: str) -> bool:
        logger.debug('device: {} uninstall pkg: {}'.format(self, pkg_name))
        return self.adb_run('uninstall {}'.format(pkg_name))[0] == 0

    def adb_start_pkg(self, pkg_name: str) -> bool:
        logger.debug('device: {} start pkg: {}'.format(self, pkg_name))
        return self.adb_run('adb shell monkey -p {} -c android.intent.category.LAUNCHER 1'.format(pkg_name))[0] == 0

    def adb_get_data_dir_of_pkg(self, pkg_name: str) -> (int, str):
        ret, infos = self.adb_run("shell dumpsys package {}".format(pkg_name))
        data_dir = list(map(lambda x: x.split(sep='dataDir=', maxsplit=1)
                            [-1], filter(lambda x: 'dataDir=' in x, infos.splitlines())))[0]
        return ret, data_dir

    def adb_grant_permission(self, pkg_name: str, permission: str) -> int:
        ret, _ = self.adb_run(
            "shell pm grant {} {}".format(pkg_name, permission))
        return ret

    def __repr__(self):
        return '<Device adb_serial={}>'.format(self.adb_serial)

    def __str__(self):
        return self.__repr__()
