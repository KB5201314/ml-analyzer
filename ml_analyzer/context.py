import logging
import hashlib

from androguard import misc
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

from . import util
from .device import Device

logger = logging.getLogger(__name__)


class Context:
    def __init__(self, apk_path: str, device: Device):
        self.apk_path: str = apk_path
        self.device: Device = device
        # analyze using androguard
        a, d, dx = misc.AnalyzeAPK(apk_path)
        self.androguard_apk: APK = a
        self.androguard_dexs: List[DalvikVMFormat] = d
        self.androguard_analysis: Analysis = dx
        # calculate md5 of apk file
        with open(apk_path, 'rb') as f:
            self.apk_sha1 = util.sha1_of_bytes(f.read())

    @property
    def package_name(self) -> str:
        return self.androguard_apk.package

    @property
    def sha1(self) -> str:
        return self.apk_sha1

    def describe(self):
        logger.info("package: {}".format(self.androguard_apk.package))
        logger.info("SHA1: {}".format(self.apk_sha1))
