import logging
from typing import List, Dict, Set, Any, Tuple

from ml_analyzer import util
from pebble import concurrent

from .base import ExtractedModel, SourceType, IExtractor
from ml_analyzer.context import Context
from ml_analyzer.mlfw import MLFrameworkType

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TFLiteExtractor(IExtractor):
    # TODO: consider TFLite metadata: https://github.com/tensorflow/tensorflow/blob/b9559be1ad7f33e63b1907ff11932cc7c1fe46ea/tensorflow/lite/g3doc/convert/metadata.md#the-flatbuffers-file-identification, https://github.com/tensorflow/tflite-support/blob/4cd0551658b6e26030e0ba7fc4d3127152e0d4ae/tensorflow_lite_support/metadata/metadata_schema.fbs#L61
    # TODO: consider TFLite in .bin or .json format (versions previous to v3): https://github.com/tensorflow/tensorflow/blob/dec8e0b11f4f87693b67e125e67dfbc68d26c205/tensorflow/lite/schema/upgrade_schema.py#L117

    def fw_type(self) -> MLFrameworkType:
        return MLFrameworkType.TF_LITE

    def extract_model(self, buf: bytes, is_exactly: bool) -> Set[bytes]:
        import tensorflow as tf

        def try_with_interpreter(maybe_model: bytes) -> bool:
            logger.debug("try_with_interpreter for a maybe_model. size: %s, content: %s...,",
                         len(maybe_model), maybe_model[:8])

            @concurrent.process(timeout=10)
            def try_with_interpreter_internal(maybe_model: bytes) -> bool:
                # setup interpreter
                interpreter = tf.lite.Interpreter(
                    model_content=maybe_model)
                interpreter.allocate_tensors()
            try:
                future = try_with_interpreter_internal(maybe_model)
                future.result()
                return True
            except Exception as e:
                logger.debug("this buffer may not be a tflite model. size: %s, content: %s..., error: %s",
                             len(maybe_model), maybe_model[:8], e)
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

    # TODO: test for this
    # TODO: replace `result` with something else ?
    def setup_hook_model_loading(self, context: Context, session, result):
        def callback_on_message(msg, bs):
            logger.debug(msg)
            if 'model_data' in msg.payload:
                model_string = "mem_hook_model_loading_{}_{}".format(
                    msg['payload']['model_data'], msg['payload']['model_size'])
                result[self.fw_type()].extend(
                    map(lambda model: ExtractedModel(SourceType.HOOK_MODEL_LOAD, model, model_string),
                        self.extract_model(bs, True))
                )
            elif 'model_path' in msg.payload:
                model_path = msg['payload']['model_path']
                model_string = "mem_hook_model_loading_{}".format(model_path)
                # TODO: better way to check ret here
                ret, file_content = context.device.adb_read_file(model_path)
                result[self.fw_type()].extend(
                    map(lambda model: ExtractedModel(SourceType.HOOK_MODEL_LOAD, model, model_string),
                        self.extract_model(file_content, True))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_tflite_hook_model_create.js'))
        script.on('message', callback_on_message)
        script.load()
        script.exports.run()
