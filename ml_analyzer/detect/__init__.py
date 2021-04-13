import logging
from typing import List, Dict, Set, Any, Tuple
from collections import defaultdict

import lief

from ml_analyzer.context import Context
from .base import DetectEvidence, EvidenceType, IDetector
from .tflite import TFLiteDetector

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class MLDetector:
    def __init__(self, context: Context):
        self.context = context
        # init detectors
        self.detectors: List[IDetector] = [TFLiteDetector()]

    def detect(self) -> Dict[str, List[DetectEvidence]]:
        result = defaultdict(list)
        # detect by so files
        files = self.context.androguard_apk.get_files()
        for file_name in filter(lambda file_name: file_name.startswith("lib/"), files):
            bs = self.context.androguard_apk.get_file(file_name)
            elf = lief.parse(raw=bs)
            for detector in self.detectors:
                if detector.detect_dot_so_file(elf):
                    result[detector.fw_type()].append(
                        DetectEvidence(EvidenceType.SO_FILE, file_name))
        # detect by java classes
        for idx, dex in enumerate(self.context.androguard_dexs):
            for detector in self.detectors:
                if detector.detect_dex(dex):
                    result[detector.fw_type()].append(
                        DetectEvidence(EvidenceType.DEX_FILE, 'classes{}.dex'.format('' if idx == 0 else (idx + 1))))
        return result
