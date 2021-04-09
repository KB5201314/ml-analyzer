from typing import List,  Any
from dataclasses import dataclass
from abc import abstractmethod
from enum import Enum, auto

from ml_analyzer.context import Context


class SourceType(Enum):
    ASSETS_FILE = auto()
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


class IExtractor:
    @abstractmethod
    def fw_type(self) -> str:
        raise NotImplemented

    @abstractmethod
    def extract_model(self, buf: bytes) -> List[bytes]:
        raise NotImplemented

    @abstractmethod
    def setup_hook_model_loading(self, context: Context, session, result):
        raise NotImplemented
