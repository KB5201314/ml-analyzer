import logging
import pathlib
import pickle
import sys
import lzma

from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import Analysis


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


DEAFULT_DATA_DIR = 'out'


class StorageManager:
    def __init__(self, data_dir: str = DEAFULT_DATA_DIR):
        self.data_dir = data_dir
        pathlib.Path(data_dir).mkdir(parents=True, exist_ok=True)

    def app_dir(self, sha1):
        app_dir = '{}/{}'.format(self.data_dir, sha1)
        pathlib.Path(app_dir).mkdir(parents=True, exist_ok=True)
        return app_dir

    def save_androguard_result(self, sha1, androguard_apk, androguard_analysis):
        try:
            sys.setrecursionlimit(50000)
            with lzma.open("{}/androguard_apk.p".format(self.app_dir(sha1)), "wb") as fp:
                pickle.dump(androguard_apk, fp)
            with lzma.open("{}/androguard_analysis.p".format(self.app_dir(sha1)), "wb") as fp:
                pickle.dump(androguard_analysis, fp)
        except Exception as e:
            logger.error("Failed to save androguard analysis result.", e)
        # NOTICE: there is a bug in androguard, caused that we can't use `androguard_apk` after pickle.dump() it.

    def read_androguard_result(self, sha1) -> (APK, Analysis):
        try:
            sys.setrecursionlimit(50000)
            with lzma.open("{}/androguard_apk.p".format(self.app_dir(sha1)), "rb") as fp:
                androguard_apk = pickle.load(fp)
            with lzma.open("{}/androguard_analysis.p".format(self.app_dir(sha1)), "rb") as fp:
                androguard_analysis = pickle.load(fp)
        except Exception as e:
            logger.warning(
                "Failed to load androguard analysis result. because: {}".format(e))
            return None
        return (androguard_apk, androguard_analysis)
