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
    FILE_NAME = auto()
    MAGIC_WORDS = auto()


@dataclass
class DetectEvidence:
    evidence_type: EvidenceType
    value: Any


class MLDetector:
    def __init__(self, context: Context):
        self.context = context
        # init detectors
        self.detectors: List[object] = [
            {'fw_type': MLFrameworkType.TF_LITE, 'file_name': r'.*\.tflite$|^libtensorflowlite_jni\.so$', 'magic_words':
             r'tensorflowlite|tensorflow lite|tflite|TfLiteTensor|kTfLiteUInt8|Java_org_tensorflow_lite_|Lorg/tensorflow/lite/'},
            {'fw_type': MLFrameworkType.TENSORFLOW, 'file_name': r'^libtensorflow_inference\.so$', 'magic_words':
             r'TensorFlowInference|tensorflow_inference|N10tensorflow'},
            {'fw_type': MLFrameworkType.PADDLE_MOBILE, 'file_name': r'.*\.paddle$|^libpaddle_capi_.*\.so$', 'magic_words':
             r'paddle_|PaddlePaddle'},
            {'fw_type': MLFrameworkType.PADDLE_LITE, 'file_name': r'.*\.nb$|^libpaddle.*\.so$', 'magic_words':
             r'N6paddle8lite_api|N6paddle4lite|paddle.?lite'},
            {'fw_type': MLFrameworkType.CAFFE, 'file_name': r'.*\.caffemodel$|.*\.prototxt$|.*\.protobin$', 'magic_words':
             r'\.caffemodel|\.prototxt|\.protobin|N5caffe'},
            {'fw_type': MLFrameworkType.CAFFE2,
                'file_name': r'$^', 'magic_words': r'[^5]caffe2|N6caffe2'},
            {'fw_type': MLFrameworkType.SENSETIME,
                'file_name': r'^libst_mobile\.so$', 'magic_words': r'stmobilesdk|sensetime'},
            {'fw_type': MLFrameworkType.NCNN,
                'file_name': r'^libncnn\.so$', 'magic_words': r'ncnn_'}
        ]

    # TODO: should we report detected symbols?

    def detect(self) -> Dict[MLFrameworkType, List[DetectEvidence]]:
        result = defaultdict(list)
        files = self.context.androguard_apk.get_files()
        for file_path in files:
            file_name = file_path[file_path.rfind('/')+1:]
            file_content = self.context.androguard_apk.get_file(file_path)
            for detector in self.detectors:
                # detect by file_name
                if len(file_name) > 0 and re.search(detector['file_name'], file_name, re.IGNORECASE) is not None:
                    result[detector['fw_type']].append(
                        DetectEvidence(EvidenceType.FILE_NAME, file_path))
                # detect by magic_words
                if len(file_content) > 0 and re.search(detector['magic_words'].encode(), file_content, re.IGNORECASE) is not None:
                    result[detector['fw_type']].append(
                        DetectEvidence(EvidenceType.MAGIC_WORDS, file_path))
        return result
