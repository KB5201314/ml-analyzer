import logging
from typing import List, Dict, Set, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from abc import abstractmethod

logger = logging.getLogger(__name__)


class MLExtractor:
    def __init__(self, context):
        self.context = context
        # init extractors
        self.extractors: List[IExtractor] = []

    def extract(self) -> Dict[str, bytes]:
        result = defaultdict(set)
        # extract by scan files inside apk statically
        files = self.context.androguard_apk.get_files()
        # TODO: should we also check files outside the `assets/` directory ?
        for file_name in filter(lambda file_name: file_name.startswith("assets/"), files):
            bs = self.context.androguard_apk.get_file(file_name)
            for extractor in self.extractors:
                result[extractor.fw_type()].update(
                    map(lambda model: ExtractedModel(model, file_name),
                        extractor.extract_model(bs))
                )
        # TODO: extract model by run apk on device
        return result


@dataclass
class ExtractedModel:
    content: bytes
    source: Any
    # TODO: impl __eq__ method to compare `content` only


class IExtractor:
    @abstractmethod
    def fw_type(self) -> str:
        raise NotImplemented

    @abstractmethod
    def extract_model(self, buf: bytes) -> List[bytes]:
        raise NotImplemented
