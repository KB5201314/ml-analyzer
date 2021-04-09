import logging
from typing import List, Dict, Set, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from abc import abstractmethod
import time

from ml_analyzer.context import Context
from ml_analyzer import util
from ml_analyzer.mlfw import MLFrameworkType
from .base import IRunner
from .tflite import TFLiteRunner

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class MLRunner:
    def __init__(self, context: Context):
        self.context = context
        # init extractors
        self.runner_constructors = {
            MLFrameworkType.TF_LITE: TFLiteRunner
        }

    def create_runner_of_fw(self, fw_type: MLFrameworkType) -> IRunner:
        return self.runner_constructors[fw_type](self.context)
