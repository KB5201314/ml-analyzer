#!/bin/python3
import logging

from context import Context
from detector import MLDetector
from extractor import MLExtractor


def run():
    logging.basicConfig()

    context = Context(
        apk_path="../mlapp/dataset/beauty/com.app.dimple.face.editor.apk")
    detector = MLDetector(context)
    detector.detect()


if __name__ == "__main__":
    # init logging
    logging.basicConfig()
    logger = logging.getLogger(__name__)
    run()
