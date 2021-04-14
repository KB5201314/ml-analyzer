import logging
from typing import List, Dict

from ml_analyzer.context import ContextBuilder
from ml_analyzer.mlfw import MLFrameworkType
from ml_analyzer.extract import MLExtractor, ExtractedModel

logger = logging.getLogger(__name__)


def extract_apk(apk_path) -> Dict[str, List[ExtractedModel]]:
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
    # extract_results = extract_apk(
    #     'tests/apks/com.cmever.android.ai.camera.apk')
    # assert len(extract_results[MLFrameworkType.TENSORFLOW]) > 0
