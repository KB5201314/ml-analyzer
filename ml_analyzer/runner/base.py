from typing import List,  Any
from dataclasses import dataclass
from abc import abstractmethod

from ml_analyzer.context import Context
from ml_analyzer.mlfw import MLFrameworkType


class Model:
    @abstractmethod
    def predict(self):
        raise NotImplementedError


class IRunner:
    def __init__(self, context: Context):
        self.context = context

    @abstractmethod
    def fw_type(self) -> MLFrameworkType:
        raise NotImplementedError

    @abstractmethod
    def create_model(self, buf: bytes) -> Model:
        raise NotImplementedError
