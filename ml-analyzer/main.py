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

    logger.info("Detecting ML for apk: {}".format(apk_path))
    detector = MLDetector(context)
    detect_results = detector.detect()
    logger.debug("Detecting ML result: {}".format(detect_results))


if __name__ == "__main__":
    # init logging
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
    logger = logging.getLogger(__name__)
    run()
