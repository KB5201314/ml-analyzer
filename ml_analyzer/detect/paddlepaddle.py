import logging

from androguard.core.bytecodes.dvm import DalvikVMFormat
import lief

from .base import IDetector
from ml_analyzer.mlfw import MLFrameworkType

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# TODO: write a test for this detector
class TFLiteDetector(IDetector):
    def fw_type(self) -> MLFrameworkType:
        return MLFrameworkType.PADDLE_PADDLE

    def detect_dot_so_file(self, elf: lief.ELF.Binary) -> bool:
        return super().detect_dot_so_file_by_symbol(
            elf, ['paddle_.*']) or super().detect_dot_so_file_by_dot_rodata(
            elf, [b'PaddlePaddle'])

    def detect_dex(self, dex: DalvikVMFormat) -> bool:
        return False
