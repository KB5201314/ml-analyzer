import logging
from typing import List, Dict, Set, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from abc import abstractmethod
import time

import frida
import androguard.decompiler.dad.util as androguard_util

from ml_analyzer.context import Context
from ml_analyzer import util
from .base import ExtractedModel, SourceType, IExtractor
from .tflite import TFLiteExtractor

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class MLExtractor:
    def __init__(self, context: Context):
        self.context = context
        # init extractors
        self.extractors: List[IExtractor] = [TFLiteExtractor()]

    def extract(self) -> Dict[str, List[ExtractedModel]]:
        result = defaultdict(list)
        # extract by scan files inside apk statically
        files = self.context.androguard_apk.get_files()
        # TODO: should we also check files outside the `assets/` directory ?
        for file_name in filter(lambda file_name: file_name.startswith("assets/"), files):
            bs = self.context.androguard_apk.get_file(file_name)
            for extractor in self.extractors:
                result[extractor.fw_type()].extend(
                    map(lambda model: ExtractedModel(SourceType.ASSETS_FILE, model, file_name),
                        extractor.extract_model(bs, False))
                )
        # extract model by run apk on device
        self.context.device.adb_uninstall_pkg(self.context.package_name)
        if not self.context.device.adb_install_apk(self.context.apk_path):
            logger.warning("failed to install apk. app_path: %s pkg: %s",
                           self.context.apk_path, self.context.package_name)
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
                session = frida_device.attach(pid)
            except Exception as e:
                logger.error("The application does not start as expected. app_path: %s pkg: %s err: %s",
                             self.context.apk_path, self.context.package_name, e)
                return result

            # setup extract in multiple way
            # self.setup_extract_by_scan_mem(session, result)
            # self.setup_extract_by_hook_deallocation(session, result)
            # self.setup_extract_by_hook_file_access(session, result)
            self.setup_extract_by_hook_native_call(session, result)

            # for each detector call it's setup_hook_model_loading()
            # for extractor in self.extractors:
            #     extractor.setup_hook_model_loading(
            #         self.context, session, result)
            frida_device.resume(pid)
            # sleep for a while
            time.sleep(20)
            session.detach()

        return result

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
                result[extractor.fw_type()].extend(
                    map(lambda model: ExtractedModel(SourceType.MEM_SCAN, model, model_string),
                        extractor.extract_model(bs, False))
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
                result[extractor.fw_type()].extend(
                    map(lambda model: ExtractedModel(SourceType.HOOK_DEALLOCATION, model, model_string),
                        extractor.extract_model(bs, True))
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
                result[extractor.fw_type()].extend(
                    map(lambda model: ExtractedModel(SourceType.HOOK_FILE_ACCESS, model, model_string),
                        extractor.extract_model(file_content, False))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_file_access.js'))
        script.on('message', callback_on_message)
        script.load()
        # we assume that model file size is at least 1K
        script.exports.run([files_dir])

    # TODO: test for this
    def setup_extract_by_hook_native_call(self, session, result):
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
                result[extractor.fw_type()].extend(
                    map(lambda model: ExtractedModel(SourceType.HOOK_NATIVE_CALL, model, model_string),
                        extractor.extract_model(file_content, True))
                )
        script = session.create_script(
            util.read_frida_script('extractor_script_hook_native_call.js'))
        script.on('message', callback_on_message)
        script.load()
        # we assume that model file size is at least 1K
        script.exports.run(native_methods)
