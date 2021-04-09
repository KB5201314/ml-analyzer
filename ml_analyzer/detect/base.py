from typing import Any
from dataclasses import dataclass
from abc import abstractmethod
from enum import Enum, auto

from androguard.core.bytecodes.dvm import DalvikVMFormat
import lief

from ml_analyzer.mlfw import MLFrameworkType


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
