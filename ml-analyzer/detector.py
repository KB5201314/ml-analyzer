from typing import List
import logging
from abc import abstractmethod

from context import Context

logger = logging.getLogger(__name__)


class MLDetector:
    def __init__(self, context: Context):
        self.detectors: List[IDetector] = []

    def detect(self):
        pass


class IDetector:
    @abstractmethod
    def detect_dot_so_file(self, file: bytes):
        raise NotImplemented

    @abstractmethod
    def detect_java_classes(self, file: bytes):
        raise NotImplemented
