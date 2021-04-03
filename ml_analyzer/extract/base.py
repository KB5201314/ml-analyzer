from typing import List,  Any
from dataclasses import dataclass
from abc import abstractmethod

from ml_analyzer.context import Context


@dataclass
class ExtractedModel:
    content: bytes
    source: Any
    # TODO: impl __eq__ method to compare `content` only

    def __repr__(self):
        return "<ExtractedModel: size: {} content: {}... source: {}>".format(len(self.content), self.content[:8], self.source)

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
