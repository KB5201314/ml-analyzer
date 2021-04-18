from __future__ import annotations

from typing import List
import logging
import hashlib
import mmap

from androguard import misc
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

from ml_analyzer import util
from ml_analyzer.device import Device

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class Context:
    """Context which is used to represent an apk analysis process.

    Attributes:
        apk_path: A `str` value, which indicates the path of the apk file being analyzed.
        package_name: A `str` value, which is the package name of apk.
        sha1: A `str` value, which is the sha1 value of this apk.
        device: A instance of `device.Device`, which indicates the device which is used in analysis process.
        androguard_apk: A instance of `androguard.core.bytecodes.apk.APK`.
        androguard_dexs: A instance of `androguard.core.bytecodes.dvm.DalvikVMFormat`.
        androguard_analysis: A instance of `androguard.core.analysis.analysis.Analysis`.
    """

    def __init__(self):
        pass

    def __set_apk(self, apk_path: str) -> Context:
        logger.info("Generating info for apk: {}".format(apk_path))
        self.apk_path: str = apk_path
        # calculate md5 of apk file
        MAP_POPULATE = 0x08000
        with open(apk_path, 'rb') as f:
            self._apk_bytes = mmap.mmap(f.fileno(), 0, flags=mmap.MAP_PRIVATE | MAP_POPULATE, prot=mmap.PROT_READ)
        self.apk_sha1 = util.sha1_of_bytes(self._apk_bytes)
        logger.info("Try to load androguard cache")
        r = self.storage.read_androguard_result(self.apk_sha1)
        if r is not None:
            logger.info(
                'Load androguard cache successfully')
        else:
            logger.info(
                'androguard cache not exist, so we perform analysis now')
            # analyze using androguard
            a = APK(self._apk_bytes, raw=True)
            d = []
            for dex in a.get_all_dex():
                df = DalvikVMFormat(dex, using_api=a.get_target_sdk_version())
                d.append(df)
            self.androguard_apk: APK = a
            self.androguard_dexs: List[DalvikVMFormat] = d
            # save it so that we need not to analyze it again
            logger.info(
                'Saving androguard cache')
            self.storage.save_androguard_result(
                self.apk_sha1, self.androguard_apk, self.androguard_dexs)
            # reload from cache
            r = self.storage.read_androguard_result(self.apk_sha1)
        self.androguard_apk = r[0]
        self.androguard_dexs = r[1]
        logger.info("Save generated apk info")
        self.storage.save_apk(self)
        logger.info("Generate info for apk finished")
        return self

    def __set_device(self, adb_serial: str = None) -> Context:
        device = Device(adb_serial=adb_serial)
        self.device: Device = device
        return self

    def __set_data_dir(self, data_dir: str) -> Context:
        from ml_analyzer.storage.manager import StorageManager
        self.storage: StorageManager = StorageManager(
            data_dir)
        return self

    @property
    def package_name(self) -> str:
        return self.androguard_apk.package if hasattr(self, 'androguard_apk') else None

    @property
    def sha1(self) -> str:
        return self.apk_sha1 if hasattr(self, 'apk_sha1') else None

    @property
    def apk_bytes(self) -> bytes:
        return self._apk_bytes

    # TODO: add test for this
    @property
    def permissions(self) -> [str]:
        return self.androguard_apk.permissions if hasattr(self, 'androguard_apk') else None

    def describe(self):
        logger.info("package: %s", self.package_name)
        logger.info("SHA1: %s", self.sha1)


class ContextBuilder:
    def __init__(self):
        from ml_analyzer.storage.manager import DEAFULT_DATA_DIR
        self.data_dir: str = DEAFULT_DATA_DIR

    def with_apk(self, apk_path: str) -> ContextBuilder:
        self.apk_path = apk_path
        return self

    def with_device(self, adb_serial: str = None) -> ContextBuilder:
        self.adb_serial = adb_serial
        return self

    def with_data_dir(self, data_dir: str) -> ContextBuilder:
        self.data_dir = data_dir
        return self

    def build(self) -> Context:
        context = Context()
        # TODO: allow none storage
        context._Context__set_data_dir(self.data_dir)
        if hasattr(self, 'apk_path'):
            context._Context__set_apk(self.apk_path)
        if hasattr(self, 'adb_serial'):
            context._Context__set_device(self.adb_serial)
        return context
