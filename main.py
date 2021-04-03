#!/bin/python3
import logging

import argparse

from ml_analyzer.context import Context, ContextBuilder
from ml_analyzer.storage import DEAFULT_DATA_DIR
from ml_analyzer.detect import MLDetector
from ml_analyzer.extract import MLExtractor
from ml_analyzer.device import Device


def parse_args():
    parser = argparse.ArgumentParser(
        prog='ml-analyzer', description='A ML model analysis framework.')
    parser.add_argument('--adb-serial', action='store', required=False,
                        help='A serial number which can be used to identify a connected android device. can be found in `adb device -l`. This option can be omitted if there is only one android device connected.')
    parser.add_argument('-d', '--data-dir', action='store', required=False, default=DEAFULT_DATA_DIR,
                        help='The name of the directory used to store the data. Default is `{}`.'.format(DEAFULT_DATA_DIR))
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
    args = parse_args()

    logger.info('Program running with args: {}'.format(args))

    if args.subcommand == 'detect':
        context = ContextBuilder().with_data_dir(
            args.data_dir).with_apk(args.apk).build()
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
        context = ContextBuilder().with_data_dir(args.data_dir).with_apk(
            args.apk).with_device(args.adb_serial).build()
        context.describe()
        logger.info("Extracting ML model for apk: {}".format(args.apk))
        extractor = MLExtractor(context)
        extract_results = extractor.extract()
        logger.debug("Extracting ML model result:")
        for fw_type, models in extract_results.items():
            logger.info('{}:'.format(fw_type))
            for model in models:
                logger.info('{}:'.format(model))

    elif args.subcommand == 'run':
        context = Context().with_data_dir(args.data_dir).build()


if __name__ == "__main__":
    # init logging
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.WARNING)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    run()
