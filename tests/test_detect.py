import logging
from typing import List, Dict

from ml_analyzer.context import ContextBuilder
from ml_analyzer.mlfw import MLFrameworkType
from ml_analyzer.detect import MLDetector, EvidenceType, DetectEvidence

logger = logging.getLogger(__name__)


def detect_apk(apk_path) -> Dict[MLFrameworkType, List[DetectEvidence]]:
    logger.info("Detecting ML framework for apk: %s", apk_path)
    context = ContextBuilder().with_apk(apk_path).build()
    detector = MLDetector(context)
    logger.info("Detect staring: %s", apk_path)
    detect_results = detector.detect()
    return detect_results


def test_detect():
    detect_results = detect_apk(
        'tests/apks/tflite_example_image_classification.apk')
    assert len(detect_results[MLFrameworkType.TF_LITE]) > 0
