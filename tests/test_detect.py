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
    detect_results = detect_apk(
        'tests/apks/com.cmever.android.ai.camera.apk')
    assert len(detect_results[MLFrameworkType.TENSORFLOW]) > 0
    detect_results = detect_apk(
        'tests/apks/paddlepaddle-moile-paddlepaddle_demo_debug.apk')
    assert len(detect_results[MLFrameworkType.PADDLE_MOBILE]) > 0
    detect_results = detect_apk(
        'tests/apks/paddle-lite-mobilenet_classification_demo.apk')
    assert len(detect_results[MLFrameworkType.PADDLE_LITE]) > 0
    detect_results = detect_apk(
        'tests/apks/caffe-com.wizzair.WizzAirApp.apk')
    assert len(detect_results[MLFrameworkType.CAFFE]) > 0
    detect_results = detect_apk(
        'tests/apks/caffe2-com.facebook.arstudio.player.apk')
    assert len(detect_results[MLFrameworkType.CAFFE2]) > 0
    detect_results = detect_apk(
        'tests/apks/sensetime_com.camera.galaxyx.apk')
    assert len(detect_results[MLFrameworkType.SENSETIME]) > 0
    detect_results = detect_apk(
        'tests/apks/ncnn-com.tencent.styletransferncnn-debug.apk')
    assert len(detect_results[MLFrameworkType.NCNN]) > 0
