#!/usr/bin/python3
"""
#!/usr/bin/env python
"""


import logging
import argparse
import global_variables
from pathlib import Path

from analysis.AndroidImageAnalysis import AndroidImageAnalysis
from analysis.LinuxDistributionAnalysis import LinuxDistributionAnalysis
from initialize_database import initialize_database


def setup_logging(image_path: str):
    root_logger = logging.root
    root_logger.setLevel(logging.INFO)
    logging_file = Path(image_path).name + '_analysis.log'
    file_handler = logging.FileHandler(logging_file)
    file_handler.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('image_path', help='Path to the image file to analyze')
    parser.add_argument('distribution',
                        help='The name you want to use in the database, e.g., the distribution "Ubuntu"')
    os_group = parser.add_mutually_exclusive_group()
    os_group.add_argument('--android', action='store_true', help='Analyze an Android based image')
    os_group.add_argument('--linux', action='store_true', help='Analyze an Linux image (only Ubuntu and Debian '
                                                               'supported)')
    parser.add_argument('-i', '--ignore-unsafe', action='store_true', help='Re-run the experiments without checking if '
                                                                           'binary was compiled from unsafe language')
    parser.add_argument('-e', '--error-static-exit', action='store_true', help='Re-run analysis of all binaries that '
                                                                               'could not be analyzed because of '
                                                                               'static_exit error')
    parser.add_argument('-m', '--only-multi-module', action='store_true', help='Only run the multi-module CFI check')
    parser.add_argument('-s', '--skip-database-check', action='store_true', help='Always run analysis regardless of existence in database')
    args: argparse.Namespace = parser.parse_args()

    try:
        global_variables.setup_global_variables()
        setup_logging(args.image_path)
        initialize_database()
        analysis = None

        if args.android:
            analysis = AndroidImageAnalysis(args.distribution, Path(args.image_path),
                                            args.ignore_unsafe, args.error_static_exit, args.only_multi_module, args.skip_database_check)
        if args.linux:
            analysis = LinuxDistributionAnalysis(args.distribution, Path(args.image_path),
                                                 args.ignore_unsafe, args.error_static_exit, args.only_multi_module, args.skip_database_check)
        analysis.run()
    except OSError as e:
        logging.error(f'Analysis stop because of {e}')
    finally:
        global_variables.cleanup_global_variables()
