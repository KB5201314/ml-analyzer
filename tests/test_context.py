import logging
import time
import os

from androguard import misc
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
import pytest

from ml_analyzer.context import ContextBuilder

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def test_analysis_cache(caplog):
    # remove cache first
    try:
        os.remove(
            'out/androguard/26f1bcd861e109531f5ca8e9a8a8cd8037400fbb_androguard_apk.p')
    except FileNotFoundError as _:
        pass
    try:
        os.remove(
            'out/androguard/26f1bcd861e109531f5ca8e9a8a8cd8037400fbb_androguard_dexs.p')
    except FileNotFoundError as _:
        pass
    # test load without cache
    context = ContextBuilder().with_apk(
        'tests/apks/tflite_example_image_classification.apk').build()
    context.describe()
    # test load with cache
    context = ContextBuilder().with_apk(
        'tests/apks/tflite_example_image_classification.apk').build()
    context.describe()

    assert 'androguard cache not exist' in caplog.text
    assert 'Load androguard cache successfully' in caplog.text


# this is just a benchmark
@pytest.mark.skip()
def test_androguard_speed():
    with open('tests/apks/tflite_example_image_classification.apk', 'rb') as f:
        bs = f.read()
    logger.info('file loaded, length: %s' % len(bs))
    # analysis with misc.AnalyzeAPK
    start = time.time()
    a, d, dx = misc.AnalyzeAPK(bs, raw=True)
    end = time.time()
    elapsed_time_1 = end - start
    logger.info('elapsed_time_1: %s' % elapsed_time_1)
    # analysis with Apk and DalvikVMFormat
    start = time.time()
    a = APK(bs, raw=True)
    d = []
    for dex in a.get_all_dex():
        df = DalvikVMFormat(dex, using_api=a.get_target_sdk_version())
        d.append(df)
    end = time.time()
    elapsed_time_2 = end - start
    logger.info('elapsed_time_2: %s' % elapsed_time_2)
    logger.info('time cost compare: %ss : %ss = %s' %
                (elapsed_time_1, elapsed_time_2, elapsed_time_1/elapsed_time_2))
