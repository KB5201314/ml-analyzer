import logging

from ml_analyzer import extract

logger = logging.getLogger(__name__)


def test_tflite_extract_model():
    model_path = 'tests/models/mobilenet_v1_1.0_224_quant.tflite'
    bs = open(model_path, 'rb').read()
    ext = extract.tflite.TFLiteExtractor()
    # test normal tflite model (with b'TFL3' as magic number)
    models = ext.extract_model(bs, 0)
    assert len(models) == 1
    assert list(models)[0] == bs
    # test file with b'TFL3' as magic number, but missing front part
    bad_model_1 = bs[2:]
    models = ext.extract_model(bad_model_1, 0)
    assert len(models) == 0
    # TODO: we have no way to check out a model which missing tail
    # # test file with b'TFL3' as magic number, but missing tail
    # bad_model_2 = bs[:-1000]
    # models = ext.extract_model(bad_model_2, 0)
    # assert len(models) == 0
    # test file composed with two tflite files
    bad_model_3 = bs + bs
    models = ext.extract_model(bad_model_3, 0)
    assert len(models) == 2
    assert models == {bad_model_3, bs}
