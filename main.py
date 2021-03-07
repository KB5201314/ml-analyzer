#!/bin/python3
import logging

import argparse

from ml_analyzer.context import Context
from ml_analyzer.detector import MLDetector
from ml_analyzer.extractor import MLExtractor
from ml_analyzer.device import Device


def parse_args():
    parser = argparse.ArgumentParser(
        prog='ml-analyzer', description='A ML model analysis framework.')
    parser.add_argument('--adb-serial', action='store', required=False,
                        help='A serial number which can be used to identify a connected android device. can be found in `adb device -l`.')
    subparsers = parser.add_subparsers(
        required=True, dest='subcommand', help='sub-command help')
    parser_detect = subparsers.add_parser(
        name='detect', description='Detect ML framework which this application use.')
    parser_detect.add_argument(
        '--apk', action='store', required=True, help='Path of apk file')
    parser_extract = subparsers.add_parser(
        name='extract', description='Detect ML framework which this application use.')
    parser_extract.add_argument(
        '--apk', action='store', required=True, help='Path of apk file')
    parser_run = subparsers.add_parser(
        name='run', description='Detect ML framework which this application use.')
    args = parser.parse_args()
    return args


def run():
    logger.setLevel(logging.DEBUG)
    args = parse_args()

    logger.info('Program running with args: {}'.format(args))

    if args.subcommand == 'detect':
        context = Context().with_apk(args.apk)
        context.describe()
        logger.info("Detecting ML framework for apk: {}".format(args.apk))
        detector = MLDetector(context)
        detect_results = detector.detect()
        logger.info("Detecting ML framework result:")
        for fw_type, evidences in detect_results.items():
            logger.info('{}:'.format(fw_type))
            for evidence in evidences:
                logger.info('{}:'.format(evidence))

    elif args.subcommand == 'extract':
        context = Context().with_apk(args.apk).with_device(args.adb_serial)
        context.describe()
        logger.info("Extracting ML model for apk: {}".format(args.apk))
        extractor = MLExtractor(context)
        extract_results = extractor.extract()
        logger.debug("Extracting ML model result: {}".format(extract_results))

    elif args.subcommand == 'run':
        context = Context()


if __name__ == "__main__":
    # init logging
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
    logger = logging.getLogger(__name__)
    run()
