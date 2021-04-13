from typing import Any, List
from dataclasses import dataclass
from abc import abstractmethod
from enum import Enum, auto
import re
import logging


from androguard.core.bytecodes.dvm import DalvikVMFormat
import lief

from ml_analyzer.mlfw import MLFrameworkType


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class EvidenceType(Enum):
    SO_FILE = auto()
    DEX_FILE = auto()


@dataclass
class DetectEvidence:
    evidence_type: EvidenceType
    value: Any


class IDetector:
    @abstractmethod
    def fw_type(self) -> MLFrameworkType:
        raise NotImplementedError

# TODO: should we report detected symbols
    @abstractmethod
    def detect_dot_so_file(self, elf: lief.ELF.Binary) -> bool:
        raise NotImplementedError

    @abstractmethod
    def detect_dex(self, dex: DalvikVMFormat) -> bool:
        raise NotImplementedError

    def detect_dot_so_file_by_symbol(self, elf: lief.ELF.Binary, symbol_patterns: List[str]):
        return any(map(
            lambda symbol: any(map(lambda pattern: re.search(pattern, symbol.name) is not None, symbol_patterns)), elf.symbols))

    def detect_dot_so_file_by_dot_rodata(self, elf: lief.ELF.Binary, contains: List[bytes]):
        detected_by_rodata = False
        try:
            # TODO: scan on any other section? https://man7.org/linux/man-pages/man5/elf.5.html
            section = elf.get_section('.rodata')
            section_content = bytes(section.content)
            detected_by_rodata = any(
                map(lambda s: s in section_content, contains))
        except lief.not_found as e:
            logger.debug("error when detect by .rodata, %s", e)

        return detected_by_rodata

    def detect_dex_by_class_name(self, dex: DalvikVMFormat, classname_patterns: List[str]) -> bool:
        # detect by package name
        classes_names = dex.get_classes_names()
        return any(map(lambda s: any(map(lambda pattern: re.search(pattern, s) is not None, classname_patterns)), classes_names))
        # TODO: should we detect by strings?
