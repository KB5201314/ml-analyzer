import logging

from androguard.core.bytecodes.dvm import DalvikVMFormat
import lief

from .base import IDetector

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# TODO: write a test for this detector
class TensorFlowLiteDetector(IDetector):
    def fw_type(self):
        return "TensorFlow Lite"

    def detect_dot_so_file(self, elf: lief.ELF.Binary) -> bool:
        # detect by symbol
        # TODO: tyr to use symbols specificed here https://github.com/tensorflow/tensorflow/blob/master/tensorflow/tools/def_file_filter/def_file_filter.py.tpl
        detected_by_symbol = any(map(lambda s: s.name.startswith(
            'TfLite') or s.name.startswith('Java_org_tensorflow_lite_'), elf.symbols))
        if detected_by_symbol:
            return True
        # detect by .rodata
        try:
            # TODO: scan on any other section? https://man7.org/linux/man-pages/man5/elf.5.html
            section = elf.get_section('.rodata')
            section_content = bytes(section.content)
            detected_by_rodata = b'TfLiteTensor' in section_content or b'kTfLiteUInt8' in section_content
            if detected_by_rodata:
                return True
        except lief.not_found as e:
            logger.debug("error when detect by .rodata, {}".format(e))
        return False

    def detect_dex(self, dex: DalvikVMFormat) -> bool:
        # detect by package name
        classes_names = dex.get_classes_names()
        if 'Lorg/tensorflow/lite/TensorFlowLite;' in classes_names:
            return True
        # TODO: should we detect by strings?
        return False
