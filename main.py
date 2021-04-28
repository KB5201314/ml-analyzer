#!/bin/python3
import logging

import argparse

from ml_analyzer.context import ContextBuilder
from ml_analyzer.storage.manager import StorageManager, DEAFULT_DATA_DIR
from ml_analyzer.detect import MLDetector
from ml_analyzer.extract import MLExtractor
from ml_analyzer.analysis.apk import ApkAnalyzer
from ml_analyzer.analysis.model import ModelAnalyzer


def parse_args():
    parser = argparse.ArgumentParser(
        prog='ml-analyzer', description='A ML model analysis framework.')
    parser.add_argument('--adb-serial', action='store', required=False,
                        help='A serial number which can be used to identify a connected android device. can be found in `adb device -l`. This option can be omitted if there is only one android device connected.')
    parser.add_argument('--no-adb-device', action='store_true', required=False,
                        help='Do not connect to adb device')
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
    parser_extract.add_argument(
        '--no-static', action='store_true', required=False, help='Do not try extract statically')
    parser_extract.add_argument(
        '--no-dynamic', action='store_true', required=False, help='Do not try extract dynamically')
    parser_analysis_model = subparsers.add_parser(
        name='analysis-model', description='Analysis dumped model file.')
    parser_analysis_model.add_argument(
        '--model-hash', action='store', required=True, help='Hash value of model file')
    parser_analysis_apk = subparsers.add_parser(
        name='analysis-apk', description='Analysis apk file.')
    parser_analysis_apk.add_argument(
        '--apk', action='store', required=True, help='Path of apk file')
    parser_analysis_apk.add_argument(
        '--flowdroid-file', action='store', required=False, help='Path of generated flowdroid input sources and sinks file')
    parser_attack = subparsers.add_parser(
        name='attack', description='Attack a model')
    parser_attack.add_argument(
        '--model-hash', action='store', required=True, help='Hash value of model file')

    args = parser.parse_args()
    return args


def run():
    args = parse_args()

    logger.info('Program running with args: %s', args)

    if args.subcommand == 'detect':
        context = ContextBuilder().with_data_dir(
            args.data_dir).with_apk(args.apk).build()
        context.describe()
        logger.info("Detecting ML framework for apk: %s", args.apk)
        detector = MLDetector(context)
        detect_results = detector.detect()
        logger.info("Detecting ML framework result:")
        for fw_type, evidences in detect_results.items():
            logger.info('%s:', fw_type)
            for evidence in evidences:
                logger.info('%s:', evidence)
        context.storage.save_detect_framework_results(context, detect_results)

    elif args.subcommand == 'extract':
        builder = ContextBuilder().with_data_dir(args.data_dir).with_apk(
            args.apk)
        if not args.no_adb_device:
            builder.with_device(args.adb_serial)
        context = builder.build()

        context.describe()
        logger.info("Extracting ML model for apk: %s", args.apk)
        extractor = MLExtractor(context, args)
        extract_results = extractor.extract()
        logger.debug("Extracting ML model result:")
        for fw_type, models in extract_results.items():
            logger.info('%s:', fw_type)
            for model in models:
                logger.info('%s:', model)
        context.storage.save_extract_model_results(context, extract_results)

    elif args.subcommand == 'analysis-model':
        logger.info("Analysis ML model: %s", args.model_hash)
        context = ContextBuilder().with_data_dir(args.data_dir).build()
        analyzer = ModelAnalyzer(context, args)
        analyzer.analysis()

    elif args.subcommand == 'analysis-apk':
        context = ContextBuilder().with_data_dir(
            args.data_dir).with_apk(args.apk).build()
        context.describe()
        logger.info("Analysis ML apk: %s", args.apk)
        analyzer = ApkAnalyzer(context, args)
        analyzer.analysis()

    elif args.subcommand == 'attack':
        pass


if __name__ == "__main__":
    # init logging
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.WARNING)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    run()
