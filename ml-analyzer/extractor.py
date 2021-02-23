
import logging
from abc import abstractmethod

logger = logging.getLogger(__name__)


class MLExtractor:
    def __init__(self, context):
        pass


class IExtractor:
    @abstractmethod
    def extract_model(self, buf: bytes, exactly_size: bool):
        raise NotImplemented
