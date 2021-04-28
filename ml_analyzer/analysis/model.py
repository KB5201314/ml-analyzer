import logging
from typing import List
from signal import signal, SIGINT
import sys

import androguard.decompiler.dad.util as androguard_util
from androguard.core.bytecodes.dvm import EncodedMethod, DalvikVMFormat
import netron

from ml_analyzer.context import Context


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ModelAnalyzer:
    def __init__(self, context: Context, args):
        self.context = context
        self.args = args

    def analysis(self):
        def stop(signal_received, frame):
            netron.stop()
            logger.info("netron stopped.")
            sys.exit(0)

        # get model path
        model_path = self.context.storage.get_model_data_path(
            self.args.model_hash)
        signal(SIGINT, stop)
        netron.start(model_path)
