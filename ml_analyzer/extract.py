import logging
from typing import List, Dict, Set, Any, Tuple, Callable
from dataclasses import dataclass
from collections import defaultdict
from abc import abstractmethod
import time
from enum import Enum, auto
import re

import frida
import androguard.decompiler.dad.util as androguard_util
from pebble import concurrent
import tensorflow as tf

from ml_analyzer.context import Context
from ml_analyzer import util
from ml_analyzer.mlfw import MLFrameworkType

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


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


class MLExtractor:
    def __init__(self, context: Context):
        self.context = context
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
                'model_checker_function': tflite_try_with_interpreter
            }
        ]

    def extract(self) -> Dict[str, List[ExtractedModel]]:
        result = defaultdict(list)
        # extract statically
        # extract by scan files inside apk
        files = self.context.androguard_apk.get_files()
        # we will also check files outside the `assets/` directory
        for file_path in files:
            file_name = file_path[file_path.rfind('/')+1:]
            file_content = self.context.androguard_apk.get_file(file_path)
            for extractor in self.extractors:
                # check model_name in static file
                if re.search(extractor['model_name'], file_name, re.IGNORECASE) is not None:
                    result[extractor['fw_type']].append(
                        ExtractedModel(SourceType.STATIC_FILE,
                                       file_content, file_path)
                    )
                # check magic_number in static file
                result[extractor['fw_type']].extend(
                    map(lambda model: ExtractedModel(SourceType.STATIC_FILE, model, file_path),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], file_content, True))
                )

        # extract dynamically
        # extract model by run apk on device
        pid = self.install_and_swap_applicion()
        if pid is None:
            logger.warning(
                'Failed to swap applicaion, we will using static extractor only: %s', self.context.package_name)
            return result

        frida_device: frida.core.Device = self.context.device.frida_device
        session = frida_device.attach(pid)

        # setup extract in multiple way
        self.setup_extract_by_scan_mem(session, result)
        self.setup_extract_by_hook_deallocation(session, result)
        self.setup_extract_by_hook_file_access(session, result)
        self.setup_extract_by_hook_jni_call(session, result)

        # for each framework, we hook specific model_load function
        for extractor in self.extractors:
            self.setup_extract_by_hook_model_loading(
                extractor, session, result)
        frida_device.resume(pid)
        # sleep for a while
        time.sleep(30)
        session.detach()

        return result

    def install_and_swap_applicion(self) -> int:
        if not hasattr(self.context, 'device'):
            logger.error("failed to install apk. app_path: %s pkg: %s: no `device` in this context, maybe is not initialized.",
                         self.context.apk_path, self.context.package_name)
            return None
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
            try:
                pid = frida_device.spawn(self.context.package_name)
                # TODO: what about child process ?
                return pid
            except Exception as e:
                logger.error("The application does not start as expected. app_path: %s pkg: %s err: %s",
                             self.context.apk_path, self.context.package_name, e)
                return None

    def extract_models_by_magic_number(self, magic_numbers: List[Tuple[bytes, int]], model_checker_function: Callable[[bytes], bool],  buf: bytes, is_exactly: bool) -> Set[bytes]:
        # buf -> is_exactly or model_checker_function is None -> magic_numbers not empty -> check by magic_numbers -> accept
        #                                                    +                      +                         +-> deny
        #                                                    +                      +-> model_checker is not None -> check by model_checker -> accept
        #                                                    +                                                   +-> deny
        #                                                    +-> magic_numbers not empty -> search position by magic_numbers and check by model_checker -> accept
        #                                                                               +                                                              +-> deny
        #                                                                               +-> check by model_checker -> accept
        #                                                                                                         +-> deny
        models = set()
        # we cannot give any evaluation when model_checker_function is None, just treat it as a exactly file
        if is_exactly or (model_checker_function is None):
            if len(magic_numbers) > 0:
                if any(map(lambda mn: buf[mn[1]: mn[1] + len(mn[0])] == mn[0], magic_numbers)):
                    models.add(buf)
            elif model_checker_function is not None:
                if model_checker_function(buf):
                    models.add(buf)
        else:
            # if the buf can not be determined exactly as a model, we need to search for magic bytes
            # things about identifiers in flatbuffers: https://github.com/dvidelabs/flatcc#file-and-type-identifiers
            for magic, offset in magic_numbers:
                cur_pos = -1
                while True:
                    cur_pos = buf.find(magic, cur_pos + 1)
                    if cur_pos == -1 or cur_pos < len(magic):
                        break
                    # accroding to flatbuffers's file format, we have no (direct) way to get the file length, so we intercept the remainder directly
                    maybe_model = buf[(cur_pos - offset):]
                    if model_checker_function(maybe_model):
                        models.add(maybe_model)
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
                result[extractor['fw_type']].extend(
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
                result[extractor['fw_type']].extend(
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

        def callback_on_message(msg):
            logger.debug(msg)
            file_path = msg['payload']['file_path']
            # TODO: better way to check ret here
            ret, file_content = self.context.device.adb_read_file(file_path)
            model_string = "mem_hook_file_access_{}".format(file_path)
            for extractor in self.extractors:
                result[extractor['fw_type']].extend(
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
                result[extractor['fw_type']].extend(
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
                result[extractor['fw_type']].extend(
                    map(lambda model: ExtractedModel(SourceType.HOOK_MODEL_LOAD, model, model_string),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], bs, True))
                )
            elif 'model_path' in msg.payload:
                model_path = msg['payload']['model_path']
                model_string = "mem_hook_model_loading_{}".format(model_path)
                # TODO: better way to check ret here
                ret, file_content = self.context.device.adb_read_file(
                    model_path)
                result[extractor['fw_type']].extend(
                    map(lambda model: ExtractedModel(SourceType.HOOK_MODEL_LOAD, model, model_string),
                        self.extract_models_by_magic_number(extractor['magic_numbers'], extractor['model_checker_function'], file_content, True))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_model_load.js'))
        script.on('message', callback_on_message)
        script.load()
        script.exports.run(extractor['model_load_functions'])


def tflite_try_with_interpreter(maybe_model: bytes) -> bool:
    logger.debug("tflite_try_with_interpreter for a maybe_model. size: %s, content: %s...,",
                 len(maybe_model), maybe_model[:8])

    @concurrent.process(timeout=10)
    def tflite_try_with_interpreter_internal(maybe_model: bytes) -> bool:
        # setup interpreter
        interpreter = tf.lite.Interpreter(
            model_content=maybe_model)
        interpreter.allocate_tensors()
    try:
        future = tflite_try_with_interpreter_internal(maybe_model)
        future.result()
        return True
    except Exception as e:
        logger.debug("this buffer may not be a tflite model. size: %s, content: %s..., error: %s",
                     len(maybe_model), maybe_model[:8], e)
        return False
