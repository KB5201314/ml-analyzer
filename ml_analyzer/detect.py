import logging
from typing import List, Dict, Set, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum, auto
import re

from androguard.core.bytecodes.dvm import DalvikVMFormat

from ml_analyzer.context import Context
from ml_analyzer.mlfw import MLFrameworkType

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class EvidenceType(Enum):
    MODEL_NAME = auto()
    MAGIC_WORDS = auto()


@dataclass
class DetectEvidence:
    evidence_type: EvidenceType
    value: Any


class MLDetector:
    def __init__(self, context: Context):
        self.context = context
        # init detectors
        self.detectors: List[object] = [{'fw_type': MLFrameworkType.TF_LITE, 'model_name': r'.*\.tflite$', 'magic_words':
                                         r'tensorflowlite|tensorflow lite|tflite|TfLiteTensor|kTfLiteUInt8|Java_org_tensorflow_lite_|Lorg/tensorflow/lite/'},
                                        {'fw_type': MLFrameworkType.PADDLE_MOBILE, 'model_name': r'$^', 'magic_words':
                                         r'paddle_|PaddlePaddle'}]

    # TODO: should we report detected symbols?

    def detect(self) -> Dict[MLFrameworkType, List[DetectEvidence]]:
        result = defaultdict(list)
        files = self.context.androguard_apk.get_files()
        for file_path in files:
            file_name = file_path[file_path.rfind('/')+1:]
            file_content = self.context.androguard_apk.get_file(file_path)
            for detector in self.detectors:
                # detect by model_name
                if re.search(detector['model_name'], file_name) is not None:
                    result[detector['fw_type']].append(
                        DetectEvidence(EvidenceType.MODEL_NAME, file_path))
                # detect by magic_words
                if re.search(detector['magic_words'].encode(), file_content) is not None:
                    result[detector['fw_type']].append(
                        DetectEvidence(EvidenceType.MODEL_NAME, file_path))
        return result
