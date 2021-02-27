import logging
from typing import List, Dict, Set, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from abc import abstractmethod
from pebble import concurrent

import tensorflow as tf

logger = logging.getLogger(__name__)


class MLExtractor:
    def __init__(self, context):
        self.context = context
        # init extractors
        self.extractors: List[IExtractor] = []

    def extract(self) -> Dict[str, bytes]:
        result = defaultdict(set)
        # extract by scan files inside apk statically
        files = self.context.androguard_apk.get_files()
        # TODO: should we also check files outside the `assets/` directory ?
        for file_name in filter(lambda file_name: file_name.startswith("assets/"), files):
            bs = self.context.androguard_apk.get_file(file_name)
            for extractor in self.extractors:
                result[extractor.fw_type()].update(
                    map(lambda model: ExtractedModel(model, file_name),
                        extractor.extract_model(bs, False))
                )
        # TODO(2021-02-25):: extract model by run apk on device

        # TODO(2021-02-25): impl TensorFlowLiteDetector

        return result


@dataclass
class ExtractedModel:
    content: bytes
    source: Any
    # TODO: impl __eq__ method to compare `content` only


class IExtractor:
    @abstractmethod
    def fw_type(self) -> str:
        raise NotImplemented

    @abstractmethod
    def extract_model(self, buf: bytes) -> List[bytes]:
        raise NotImplemented


class TensorFlowLiteDetector:
    # TODO: consider TFLite metadata: https://github.com/tensorflow/tensorflow/blob/b9559be1ad7f33e63b1907ff11932cc7c1fe46ea/tensorflow/lite/g3doc/convert/metadata.md#the-flatbuffers-file-identification, https://github.com/tensorflow/tflite-support/blob/4cd0551658b6e26030e0ba7fc4d3127152e0d4ae/tensorflow_lite_support/metadata/metadata_schema.fbs#L61
    # TODO: consider TFLite in .bin or .json format (versions previous to v3): https://github.com/tensorflow/tensorflow/blob/dec8e0b11f4f87693b67e125e67dfbc68d26c205/tensorflow/lite/schema/upgrade_schema.py#L117

    def fw_type(self) -> str:
        return 'TensorFlow Lite'

    def extract_model(self, buf: bytes, is_exactly: bool) -> Set[bytes]:
        def try_with_interpreter(maybe_model: bytes) -> bool:
            logger.debug("try_with_interpreter for a maybe_model. size: {}, content: {}...,".format(
                len(maybe_model), maybe_model[:8]))
            try:
                @concurrent.process(timeout=10)
                def try_with_interpreter_internal(maybe_model: bytes) -> bool:
                    interpreter = tf.lite.Interpreter(model_content=maybe_model)
                    interpreter.allocate_tensors()
                future = try_with_interpreter_internal(maybe_model)
                future.result()
                return True
            except Exception as e:
                logger.debug("this buffer may not be a tflite model. size: {}, content: {}..., error: {}".format(
                    len(maybe_model), maybe_model[:8], e))
                return False

        models = set()
        if not is_exactly:
            # if the buf can not be determined exactly as a model, we need to search for magic bytes
            # things about identifiers in flatbuffers: https://github.com/dvidelabs/flatcc#file-and-type-identifiers
            offset = -1
            while True:
                offset = buf.find(b"TFL3", offset + 1)
                if offset == -1 or offset < 4:
                    break
                # accroding to flatbuffers's file format, we have no (direct) way to get the file length, so we intercept the remainder directly
                # TODO: any other way to get file length ? https://github.com/tensorflow/tensorflow/blob/e43be76009614be88454d2fdf2fe702acc5bab77/tensorflow/lite/tools/verifier.cc#L64
                maybe_model = buf[(offset-4):]
                if try_with_interpreter(maybe_model):
                    models.add(maybe_model)
        # In either case, we will try the entire file again, so as not to miss the absence of magic words
        maybe_model = buf
        if try_with_interpreter(maybe_model):
            models.add(maybe_model)
        return models


# TODO: try pytest and add github action
