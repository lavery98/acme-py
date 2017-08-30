#!/usr/bin/env python

import argparse
import json
import sys
import logging

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

# Default config
CA_API_URL = "http://127.0.0.1:14000"
API_DIR_NAME = "dir"

# Logger
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None, help="Configuration file")
    parser.add_argument("--acme-dir", default=None, help="Path to the ACME challenge directory")

    challenges = parser.add_mutually_exclusive_group(required=True)
    challenges.add_argument("--http", action="store_true", help="Use HTTP challenge")
    #challenges.add_argument("--tls", action="store_true", help="Use TLS challenge")
    challenges.add_argument("--dns", action="store_true", help="Use DNS challenge")

    logging_amount = parser.add_mutually_exclusive_group()
    logging_amount.add_argument("--debug", action="store_true", help="Enable debug log messages")
    logging_amount.add_argument("--quiet", action="store_true", help="Disable logging apart from errors")

    args = parser.parse_args(argv)

    if args.http and not args.acme_dir:
        parser.error("--acme-dir is required for the HTTP challenge")

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    if args.quiet:
        LOGGER.setLevel(logging.ERROR)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
