import logging
from typing import Set, Dict

from ml_analyzer.context import ContextBuilder
from ml_analyzer.mlfw import MLFrameworkType
from ml_analyzer.extract import MLExtractor, ExtractedModel

logger = logging.getLogger(__name__)


def extract_apk(apk_path) -> Dict[str, Set[ExtractedModel]]:
    logger.info("Extracting ML framework for apk: %s", apk_path)
    context = ContextBuilder().with_apk(apk_path).build()
    extractor = MLExtractor(context)
    logger.info("Extract staring: %s", apk_path)
    extract_results = extractor.extract()
    return extract_results


def test_tflite_extract_model():
    extract_results = extract_apk(
        'tests/apks/tflite_example_image_classification.apk')
    assert len(extract_results[MLFrameworkType.TF_LITE]) > 0
    extract_results = extract_apk(
        'tests/apks/com.cmever.android.ai.camera.apk')
    assert len(extract_results[MLFrameworkType.TENSORFLOW]) > 0
    extract_results = extract_apk(
        'tests/apks/paddlepaddle-moile-paddlepaddle_demo_debug.apk')
    assert len(extract_results[MLFrameworkType.PADDLE_MOBILE]) > 0
    extract_results = extract_apk(
        'tests/apks/paddle-lite-mobilenet_classification_demo.apk')
    assert len(extract_results[MLFrameworkType.PADDLE_LITE]) > 0
    extract_results = extract_apk(
        'tests/apks/caffe-com.wizzair.WizzAirApp.apk')
    assert len(extract_results[MLFrameworkType.CAFFE]) > 0
