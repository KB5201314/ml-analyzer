#!/bin/python3
import logging

from context import Context
from detector import MLDetector
from extractor import MLExtractor


def run():
    logger.setLevel(logging.DEBUG)

    apk_path = "../mlapp/dataset/beauty/com.dsrtech.lipsy.apk"
    logger.info("Generating info for apk: {}".format(apk_path))
    context = Context(apk_path=apk_path)
    context.describe()

    logger.info("Detecting ML framework for apk: {}".format(apk_path))
    detector = MLDetector(context)
    detect_results = detector.detect()
    logger.debug("Detecting ML framework result: {}".format(detect_results))

    logger.info("Extracting ML model for apk: {}".format(apk_path))
    extractor = MLExtractor(context)
    extract_results = extractor.extract()
    logger.debug("Extracting ML model result: {}".format(extract_results))


if __name__ == "__main__":
    # init logging
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
    logger = logging.getLogger(__name__)
    run()
