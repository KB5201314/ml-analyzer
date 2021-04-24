from typing import List

import androguard.decompiler.dad.util as androguard_util
from androguard.core.bytecodes.dvm import EncodedMethod, DalvikVMFormat

from ml_analyzer.context import Context


class ModelAnalyzer:
    def __init__(self, context: Context):
        self.context = context

    def analysis(self):
        pass
