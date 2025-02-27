import logging
import pathlib
import pickle
import sys
import lzma
import os
import shutil
from typing import List, Dict, Set, Any, Tuple

import peewee
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import Analysis

from ml_analyzer.context import Context
from ml_analyzer.detect import DetectEvidence, EvidenceType
from ml_analyzer.extract import ExtractedModel, SourceType
from ml_analyzer import util
from .table import *

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


DEAFULT_DATA_DIR = 'out'

# setup peewee logger
# logger = logging.getLogger('peewee')
# logger.addHandler(logging.StreamHandler())
# logger.setLevel(logging.DEBUG)


class StorageManager:
    def __init__(self, data_dir: str = DEAFULT_DATA_DIR):
        self.data_dir = data_dir
        # init directory
        pathlib.Path(data_dir).mkdir(parents=True, exist_ok=True)

        pathlib.Path('{}/androguard'.format(data_dir)
                     ).mkdir(parents=True, exist_ok=True)
        pathlib.Path('{}/apk'.format(data_dir)
                     ).mkdir(parents=True, exist_ok=True)
        pathlib.Path('{}/model'.format(data_dir)
                     ).mkdir(parents=True, exist_ok=True)
        # init database
        database.init('{}/data.db'.format(data_dir))
        # TODO: init table
        database.create_tables([Apk, Model, ApkFramework, ApkModel])

    def save_androguard_result(self, sha1, androguard_apk, androguard_dexs):
        try:
            sys.setrecursionlimit(2000000)
            with lzma.open("{}/androguard/{}_androguard_apk.p".format(self.data_dir, sha1), "wb") as fp:
                pickle.dump(androguard_apk, fp)
            with lzma.open("{}/androguard/{}_androguard_dexs.p".format(self.data_dir, sha1), "wb") as fp:
                pickle.dump(androguard_dexs, fp)
        except Exception as e:
            logger.error("Failed to save androguard analysis result. %s", e)
        # NOTICE: there is a bug in androguard, caused that we can't use `androguard_apk` after pickle.dump() it.

    def read_androguard_result(self, sha1) -> (APK, Analysis):
        try:
            sys.setrecursionlimit(2000000)
            with lzma.open("{}/androguard/{}_androguard_apk.p".format(self.data_dir, sha1), "rb") as fp:
                androguard_apk = pickle.load(fp)
            with lzma.open("{}/androguard/{}_androguard_dexs.p".format(self.data_dir, sha1), "rb") as fp:
                androguard_dexs = pickle.load(fp)
        except Exception as e:
            logger.warning(
                "Failed to load androguard analysis result. because: %s", e)
            return None
        return (androguard_apk, androguard_dexs)

    def save_apk(self, context: Context):
        path = '{}/apk/{}.apk'.format(self.data_dir, context.sha1)
        # save apk to file
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                f.write(context.apk_bytes)
        # save to db
        Apk.insert(hash=context.sha1,
                   package=context.package_name, file_path=context.apk_path).on_conflict_ignore().execute()

    def save_detect_framework_results(self, context: Context, detect_results: Dict[str, List[DetectEvidence]]):
        for fw_type, evidences in detect_results.items():
            for evidence in evidences:
                # save evidence to db
                ApkFramework.get_or_create(apk_hash=context.sha1, framework=fw_type,
                                           evidence_type=evidence.evidence_type, remark=evidence.value)

    def read_detect_framework_results(self, apk_hash: str) -> List[ApkFramework]:
        results = list(ApkFramework.select().where(
            ApkFramework.apk_hash == apk_hash))
        return results

    def save_extract_model_results(self, context: Context, extract_results: Dict[str, List[ExtractedModel]]):
        for fw_type, models in extract_results.items():
            for model in models:
                sha1 = util.sha1_of_bytes(model.content)
                # save model to file
                path = '{}/model/{}.model'.format(self.data_dir, sha1)
                with open(path, 'wb') as f:
                    f.write(model.content)
                # save model to db
                Model.insert(
                    hash=sha1, framework=fw_type).on_conflict_replace().execute()
                # FIXME: duplicate apk-model mapping caused by difference type
                ApkModel.get_or_create(apk_hash=context.sha1, model_hash=sha1,
                                       source_type=model.source_type, source=model.source)

    def get_model_data_path(self, model_hash: str) -> str:
        return '{}/model/{}.model'.format(self.data_dir, model_hash)
