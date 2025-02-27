import logging
from typing import List, Dict, Set, Any, Tuple, Callable
from dataclasses import dataclass
from collections import defaultdict
import time
from enum import Enum, auto
import re
import warnings
import sys

import frida
import androguard.decompiler.dad.util as androguard_util
from pebble import concurrent
import tensorflow as tf
import paddlelite.lite as pdlite

from ml_analyzer.context import Context
from ml_analyzer import util
from ml_analyzer.mlfw import MLFrameworkType

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SourceType(Enum):
    STATIC_FILE = auto()
    MEM_SCAN = auto()
    HOOK_DEALLOCATION = auto()
    HOOK_FILE_ACCESS = auto()
    HOOK_NATIVE_CALL = auto()
    HOOK_MODEL_LOAD = auto()


@dataclass
class ExtractedModel:
    source_type: SourceType
    content: bytes
    source: Any
    # TODO: impl __eq__ method to compare `content` only

    def __repr__(self):
        return "<ExtractedModel: size: {} content: {}... source_type: {} source: {}>".format(len(self.content), self.content[:8], self.source_type, self.source)

    def __str__(self):
        return self.__repr__()

    def __hash__(self):
        return hash(hash(self.source_type) + hash(self.content))

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.source_type == other.source_type and self.content == other.content and self.source == other.source


class MLExtractor:
    def __init__(self, context: Context, no_static: bool = False, no_dynamic: bool = False):
        self.context = context
        self.no_static = no_static
        self.no_dynamic = no_dynamic

        # init extractors
        self.extractors: List[Dict[str, Any]] = [
            {
                'fw_type': MLFrameworkType.TF_LITE,
                'model_name': r'.*\.tflite$',
                'magic_numbers': [(b'TFL3', 4)],
                'model_load_functions': [
                    {
                        # https://github.com/tensorflow/tensorflow/blob/57f589f66c63fe7dd2f633c7304db78fc54aff0f/tensorflow/lite/c/c_api.cc#L90
                        # TfLiteModel* TfLiteModelCreate(const void* model_data, size_t model_size) {
                        'func_name': 'TfLiteModelCreate',
                        'param_type': 1,  # byte pointer and length
                        # the param index of pointer and length
                        'indexs': [0, 1]
                    }, {
                        # https://github.com/tensorflow/tensorflow/blob/57f589f66c63fe7dd2f633c7304db78fc54aff0f/tensorflow/lite/c/c_api.cc#L97
                        # TfLiteModel* TfLiteModelCreateFromFile(const char* model_path) {
                        'func_name': 'TfLiteModelCreateFromFile',
                        'param_type': 0,  # file path cstring
                        'indexs': [0]
                    },
                ],
                'model_checker_function': model_checker_tflite
            },
            {
                'fw_type': MLFrameworkType.TENSORFLOW,
                'model_name': r'$^',
                'magic_numbers': [],
                'model_load_functions': [],
                'model_checker_function': model_checker_tensorflow
            },
            {
                'fw_type': MLFrameworkType.PADDLE_MOBILE,
                'model_name': r'.*\.paddle$',
                'magic_numbers': [],
                'model_load_functions': [],
                # currently we cannot check it, because there is missing of some package in `paddlepaddle`: https://github.com/PaddlePaddle/Paddle/issues/15823. And paddle-mobile is deprecated
                'model_checker_function': None
            },
            {
                'fw_type': MLFrameworkType.PADDLE_LITE,
                'model_name': r'.*\.nb$',
                'magic_numbers': [],
                'model_load_functions': [],
                'model_checker_function': model_checker_paddle_lite
            },
            {
                'fw_type': MLFrameworkType.CAFFE,
                'model_name': r'.*\.caffemodel$|.*\.prototxt$|.*\.protobin$',
                'magic_numbers': [],
                'model_load_functions': [],
                'model_checker_function': model_checker_caffe
            },
            {
                'fw_type': MLFrameworkType.CAFFE2,
                'model_name': r'$^',
                'magic_numbers': [],
                'model_load_functions': [],
                'model_checker_function': model_checker_caffe2
            },
            {
                'fw_type': MLFrameworkType.SENSETIME,
                'model_name': r'$^',
                'magic_numbers': [(b'STEF', 0)],
                'model_load_functions': [],
                'model_checker_function': None
            }
        ]

    def extract(self) -> Dict[str, Set[ExtractedModel]]:
        result = defaultdict(set)
        if not self.no_static:
            logger.info("Start statically extracting.")
            # extract statically
            # extract by scan files inside apk
            files = self.context.androguard_apk.get_files()
            # we will also check files outside the `assets/` directory
            for file_path in filter(lambda p: p.startswith("assets/"), files):
                file_name = file_path[file_path.rfind('/')+1:]
                file_content = self.context.androguard_apk.get_file(file_path)
                for extractor in self.extractors:
                    # check model_name in static file
                    if len(file_name) > 0 and re.search(extractor['model_name'], file_name, re.IGNORECASE) is not None:
                        result[extractor['fw_type']].add(
                            ExtractedModel(SourceType.STATIC_FILE,
                                           file_content, file_path)
                        )
                    if len(file_content) > 0:
                        # check magic_number in static file
                        result[extractor['fw_type']].update(
                            map(lambda model: ExtractedModel(SourceType.STATIC_FILE, model, file_path),
                                self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], file_content, True))
                        )
            logger.info("End statically extracting.")

        if not self.no_dynamic:
            logger.info("Start dynamically extracting.")
            # extract dynamically
            # extract model by run apk on device
            pid = self.install_and_swap_applicion()
            if pid is None:
                logger.warning(
                    'Failed to swap applicaion, we will using static extractor only: %s', self.context.package_name)
                return result

            try:
                frida_device: frida.core.Device = self.context.device.frida_device
                session = frida_device.attach(pid)

                # setup extract in multiple way
                # self.setup_extract_by_scan_mem(session, result)
                # self.setup_extract_by_hook_deallocation(session, result)
                self.setup_extract_by_hook_file_access(session, result)
                self.setup_extract_by_hook_jni_call(session, result)

                # for each framework, we hook specific model_load function
                for extractor in self.extractors:
                    self.setup_extract_by_hook_model_loading(
                        extractor, session, result)
                frida_device.resume(pid)
                # sleep for a while
                time.sleep(30)
                logger.info("dynamically extracting timeout.")
            except Exception as e:
                logger.warning(
                    'Exception raised during extracting model dynamically: %s, error: %s', self.context.package_name, e)
            self.context.device.adb_uninstall_pkg(
                self.context.package_name)
            if session is not None:
                session.detach()
            logger.info("End dynamically extracting.")

        return result

    def install_and_swap_applicion(self) -> int:
        if not hasattr(self.context, 'device'):
            logger.error("failed to install apk. app_path: %s pkg: %s: no `device` in this context, maybe is not initialized.",
                         self.context.apk_path, self.context.package_name)
            return None
        self.context.device.adb_device_weakup()  # device weak up
        self.context.device.adb_uninstall_pkg(self.context.package_name)
        if not self.context.device.adb_install_apk(self.context.apk_path):
            logger.error("failed to install apk. app_path: %s pkg: %s",
                         self.context.apk_path, self.context.package_name)
            return None
        else:
            # grant all permissions
            for p in self.context.permissions:
                self.context.device.adb_grant_permission(
                    self.context.package_name, p)
            # spawn application program
            frida_device: frida.core.Device = self.context.device.frida_device
            self.context.device.adb_device_weakup()
            try:
                pid = frida_device.spawn(self.context.package_name)
                # TODO: what about child process ?
                return pid
            except Exception as e:
                logger.error("The application does not start as expected. app_path: %s pkg: %s err: %s",
                             self.context.apk_path, self.context.package_name, e)
                return None

    def extract_models_by_magic_number(self, magic_numbers: List[Tuple[bytes, int]], model_checker_function: Callable[[bytes], bool],  buf: bytes, is_exactly: bool) -> Set[bytes]:
        # buf -> is_exactly or or magic_numbers is empty or smodel_checker_function is None -> magic_numbers not empty -> check by magic_numbers -> accept
        #                                                                                 +                      +                         +-> deny
        #                                                                                 +                      +-> model_checker is not None -> check by model_checker -> accept
        #                                                                                 +                                                   +-> deny
        #                                                                                 +-> check by model_checker -> accept
        #                                                                                                           +-> search position by magic_numbers and check by model_checker -> accept
        #                                                                                                                                                                           +-> deny
        models = set()
        if len(buf) == 0:
            return models
        # we cannot give any evaluation when magic_numbers is empty or model_checker_function is None, just treat it as a exactly file
        if is_exactly or len(magic_numbers) == 0 or (model_checker_function is None):
            if len(magic_numbers) > 0:
                if any(map(lambda mn: buf[mn[1]: mn[1] + len(mn[0])] == mn[0], magic_numbers)):
                    models.add(buf)
            elif model_checker_function is not None:
                if model_checker_function(buf):
                    models.add(buf)
        else:
            # If the buf can not be determined exactly as a model, we need to search for magic bytes
            # But giving a check by model_checker_function is needed, because some model may not have a magic_number but is valid
            if model_checker_function(buf):
                models.add(buf)
            # things about identifiers in flatbuffers: https://github.com/dvidelabs/flatcc#file-and-type-identifiers
            for magic, offset in magic_numbers:
                cur_pos = -1
                while True:
                    cur_pos = buf.find(magic, cur_pos + 1)
                    if cur_pos == -1 or cur_pos < len(magic):
                        break
                    # Accroding to flatbuffers's file format, we have no (direct) way to get the file length, so we intercept the remainder directly.
                    # But there is a better solution: https://github.com/google/flatbuffers/issues/4258#issuecomment-642375567
                    maybe_model = buf[(cur_pos - offset):]
                    if model_checker_function(maybe_model):
                        models.add(maybe_model)
        if len(models) > 0:
            logger.info(
                "extract_models_by_magic_number(): collected %s models", len(models))
        return models

    # TODO: Determine the time to extract
    # FIXME(2020-03-08): cannot stop program
    # TODO: test for this

    def setup_extract_by_scan_mem(self, session, result):
        def callback_on_message(msg, bs):
            logger.debug(msg)
            model_string = "mem_scan_{}_{}".format(
                msg['payload']['base'], msg['payload']['size'])
            if 'file' in msg['payload']:
                model_string = "{}_{}".format(
                    model_string, msg['payload']['file']['path'])
            for extractor in self.extractors:
                result[extractor['fw_type']].update(
                    map(lambda model: ExtractedModel(SourceType.MEM_SCAN, model, model_string),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'],  bs, False))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_enumerate_ranges.js'))
        script.on('message', callback_on_message)
        script.load()
        script.exports.run()

    # TODO: test for this

    def setup_extract_by_hook_deallocation(self, session, result):
        def callback_on_message(msg, bs):
            logger.debug(msg)
            model_string = "mem_hook_deallocation_{}_{}".format(
                msg['payload']['pointer'], msg['payload']['size'])
            for extractor in self.extractors:
                result[extractor['fw_type']].update(
                    map(lambda model: ExtractedModel(SourceType.HOOK_DEALLOCATION, model, model_string),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], bs, True))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_deallocation.js'))
        script.on('message', callback_on_message)
        script.load()
        # we assume that model file size is at least 1K
        script.exports.run(1024)

    # TODO: test for this
    def setup_extract_by_hook_file_access(self, session, result):
        # get data_dir
        # TODO: better way to check ret here
        ret, data_dir = self.context.device.adb_get_data_dir_of_pkg(
            self.context.package_name)
        files_dir = '{}/files'.format(data_dir)

        def callback_on_message(msg, bs):
            logger.debug(msg)
            file_path = msg['payload']['file_path']
            # TODO: better way to check ret here
            ret, file_content = self.context.device.adb_read_file(file_path)
            model_string = "mem_hook_file_access_{}".format(file_path)
            for extractor in self.extractors:
                result[extractor['fw_type']].update(
                    map(lambda model: ExtractedModel(SourceType.HOOK_FILE_ACCESS, model, model_string),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], file_content, False))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_file_access.js'))
        script.on('message', callback_on_message)
        script.load()
        # we assume that model file size is at least 1K
        script.exports.run([files_dir])

    # TODO: test for this
    def setup_extract_by_hook_jni_call(self, session, result):
        # get all native methods
        native_methods = []
        for dex in self.context.androguard_dexs:
            for method in dex.get_methods():
                # should be native method
                if method.get_access_flags() & 0b100000000 == 0:
                    continue
                native_methods.append([util.parse_descriptor_for_frida(method.get_class_name()), method.get_name(), [
                    util.parse_descriptor_for_frida(p) for p in androguard_util.get_params_type(method.get_descriptor())]])
        # logger.debug('native_methods: {}'.format(native_methods))

        def callback_on_message(msg, bs):
            logger.debug(msg)
            file_content = bs
            # TODO: better way to check ret here
            model_string = "mem_hook_native_call"
            for extractor in self.extractors:
                result[extractor['fw_type']].update(
                    map(lambda model: ExtractedModel(SourceType.HOOK_NATIVE_CALL, model, model_string),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], file_content, True))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_jni_call.js'))
        script.on('message', callback_on_message)
        script.load()
        # we assume that model file size is at least 1K
        script.exports.run(native_methods)

    # TODO: test for this
    def setup_extract_by_hook_model_loading(self, extractor, session, result):
        def callback_on_message(msg, bs):
            logger.debug(msg)
            if 'model_data' in msg.payload:
                model_string = "mem_hook_model_loading_{}_{}".format(
                    msg['payload']['model_data'], msg['payload']['model_size'])
                result[extractor['fw_type']].update(
                    map(lambda model: ExtractedModel(SourceType.HOOK_MODEL_LOAD, model, model_string),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], bs, True))
                )
            elif 'model_path' in msg.payload:
                model_path = msg['payload']['model_path']
                model_string = "mem_hook_model_loading_{}".format(model_path)
                # TODO: better way to check ret here
                ret, file_content = self.context.device.adb_read_file(
                    model_path)
                result[extractor['fw_type']].update(
                    map(lambda model: ExtractedModel(SourceType.HOOK_MODEL_LOAD, model, model_string),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], file_content, True))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_model_load.js'))
        script.on('message', callback_on_message)
        script.load()
        script.exports.run(extractor['model_load_functions'])


def capture_and_reise_runtine_warning(func):
    with warnings.catch_warnings(record=True) as ws:
        func()
        runtime_warning = next(
            (w for w in ws if issubclass(w.category, RuntimeWarning)), None)
        if runtime_warning is not None:
            raise RuntimeError(
                'RuntimeWarning raised: {}'.format(runtime_warning))


def model_checker_tflite(maybe_model: bytes) -> bool:
    logger.debug("model_checker_tflite for a maybe_model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])

    @concurrent.process(timeout=10)
    def model_checker_tflite_internal(maybe_model: bytes) -> bool:
        util.mute_stdout_and_stderr()
        # setup interpreter
        interpreter = tf.lite.Interpreter(
            model_content=maybe_model)
        interpreter.allocate_tensors()
    try:
        future = model_checker_tflite_internal(maybe_model)
        future.result()
        return True
    except Exception as e:
        logger.debug("this buffer may not be a tflite model. size: %s, content: %s..., error: %s",
                     len(maybe_model), maybe_model[:8], e)
        return False


def model_checker_tensorflow(maybe_model: bytes) -> bool:
    logger.debug("model_checker_tensorflow for a maybe_model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])
    # https://www.tensorflow.org/tutorials/keras/save_and_load?hl=zh-cn#savedmodel_%E6%A0%BC%E5%BC%8F
    # try load GraphDef(*.pb)
    try:
        def internal_func():
            graph_def = tf.compat.v1.GraphDef()
            graph_def.ParseFromString(maybe_model)

        capture_and_reise_runtine_warning(internal_func)
        return True
    except Exception as e:
        logger.debug("failed to load with tf.compat.v1.GraphDef(), may not be a graph def file. size: %s, content: %s..., error: %s",
                     len(maybe_model), maybe_model[:8], e)

    logger.debug("this buffer may not be a tensorflow model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])
    return False


def model_checker_paddle_lite(maybe_model: bytes) -> bool:
    logger.debug("model_checker_paddle_lite for a maybe_model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])

    @concurrent.process(timeout=10)
    def model_checker_paddle_lite_internal(maybe_model: bytes):
        util.mute_stdout_and_stderr()
        config = pdlite.MobileConfig()
        config.set_model_from_buffer(maybe_model)
        pdlite.create_paddle_predictor(config)
    try:
        future = model_checker_paddle_lite_internal(maybe_model)
        future.result()
        return True
    except Exception as e:
        logger.debug("failed to load with paddlelite.lite.create_paddle_predictor(), may not be a naivebuffer file. size: %s, content: %s..., error: %s",
                     len(maybe_model), maybe_model[:8], e)
    logger.debug("this buffer may not be a paddle-lite model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])
    return False


def model_checker_caffe(maybe_model: bytes) -> bool:
    logger.debug("model_checker_caffe for a maybe_model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])
    try:
        import ml_analyzer.misc.caffe_pb2 as cp

        def internal_func():
            np = cp.NetParameter()
            np.ParseFromString(maybe_model)

        capture_and_reise_runtine_warning(internal_func)
        return True
    except Exception as e:
        logger.debug("failed to load with caffe_pb2.NetParameter(), may not be a graph def file. size: %s, content: %s..., error: %s",
                     len(maybe_model), maybe_model[:8], e)

    logger.debug("this buffer may not be a caffe model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])
    return False


def model_checker_caffe2(maybe_model: bytes) -> bool:
    logger.debug("model_checker_caffe for a maybe_model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])
    try:
        import caffe2.proto.caffe2_pb2 as cp2

        def internal_func():
            nd = cp2.NetDef()
            nd.ParseFromString(maybe_model)

        capture_and_reise_runtine_warning(internal_func)
        return True
    except Exception as e:
        logger.debug("failed to load with caffe_pb2.NetParameter(), may not be a graph def file. size: %s, content: %s..., error: %s",
                     len(maybe_model), maybe_model[:8], e)

    logger.debug("this buffer may not be a caffe model. size: %s, content: %s...",
                 len(maybe_model), maybe_model[:8])
    return False
