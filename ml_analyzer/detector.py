import logging
from typing import List, Dict, Set, Any, Tuple
from dataclasses import dataclass
from abc import abstractmethod
from collections import defaultdict

from androguard.core.bytecodes.dvm import DalvikVMFormat
import lief

from context import Context

logger = logging.getLogger(__name__)


@dataclass
class DetectEvidence:
    clazz: str
    value: Any


class MLDetector:
    def __init__(self, context: Context):
        self.context = context
        # init detectors
        self.detectors: List[IDetector] = [TensorFlowLiteDetector()]

    def detect(self) -> Dict[str, List[DetectEvidence]]:
        result = defaultdict(list)
        # detect by so files
        files = self.context.androguard_apk.get_files()
        for file_name in filter(lambda file_name: file_name.startswith("lib/"), files):
            bs = self.context.androguard_apk.get_file(file_name)
            elf = lief.parse(raw=bs)
            for detector in self.detectors:
                if detector.detect_dot_so_file(elf):
                    result[detector.fw_type()].append(
                        DetectEvidence("so_file", file_name))
        # detect by java classes
        for idx, dex in enumerate(self.context.androguard_dexs):
            for detector in self.detectors:
                if detector.detect_dex(dex):
                    result[detector.fw_type()].append(
                        DetectEvidence("dex", 'classes{}.dex'.format('' if idx == 0 else (idx + 1))))
        return result


class IDetector:
    @abstractmethod
    def fw_type(self) -> str:
        raise NotImplemented

# TODO: should we report detected symbols
    @abstractmethod
    def detect_dot_so_file(self, elf: lief.ELF.Binary) -> bool:
        raise NotImplemented

    @abstractmethod
    def detect_dex(self, dex: DalvikVMFormat) -> bool:
        raise NotImplemented


# TODO: write a test for this detector
class TensorFlowLiteDetector(IDetector):
    def fw_type(self):
        return "TensorFlow Lite"

    def detect_dot_so_file(self, elf: lief.ELF.Binary) -> bool:
        # detect by symbol
        # TODO: tyr to use symbols specificed here https://github.com/tensorflow/tensorflow/blob/master/tensorflow/tools/def_file_filter/def_file_filter.py.tpl
        detected_by_symbol = any(map(lambda s: s.name.startswith(
            'TfLite') or s.name.startswith('Java_org_tensorflow_lite_'), elf.symbols))
        if detected_by_symbol:
            return True
        # detect by .rodata
        try:
            section = elf.get_section('.rodata')            
            section_content = bytes(section.content)
            detected_by_rodata = b'TfLiteTensor' in section_content or b'kTfLiteUInt8' in section_content
            if detected_by_rodata:
                return True
        except lief.not_found as e:
            logger.debug("error when detect by .rodata, {}".format(e))
        return False

    def detect_dex(self, dex: DalvikVMFormat) -> bool:
        # detect by package name
        classes_names = dex.get_classes_names()
        if 'Lorg/tensorflow/lite/TensorFlowLite;' in classes_names:
            return True
        # TODO: should we detect by strings?
        return False
