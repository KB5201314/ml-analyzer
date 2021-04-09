import logging

from pebble import concurrent

from ml_analyzer.mlfw import MLFrameworkType
from .base import Model, IRunner


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TFLiteRunner(IRunner):
    def fw_type(self) -> MLFrameworkType:
        return MLFrameworkType.TF_LITE

    def create_model(self, buf) -> Model:
        raise NotImplementedError
